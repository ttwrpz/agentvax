"""The terms of a recurring payment, read from the owner's instruction by fixed rules (SCHEDULE_CREATE, T2).

Deterministic code with no model call. The validator uses it to check that a schedule draft's period, run count and
first due date come from what the owner wrote (provenance), whatever model drafted it, and the mock model uses it
to draft. Nothing is guessed: a term the instruction does not fix, or fixes in two different ways, is a problem,
and the agent asks.

* **Period.** ``every`` or ``each`` with an optional count and a unit ("every two weeks", "each month", "every 30
  days"), or an adverb ("weekly", "monthly"). Every period stated must agree.
* **Runs.** A count with a noun ("six times", "four payments") or a duration ("for 8 weeks", "for the next 24
  months", "for a year"), which must be a whole number of periods. Every run count stated must agree. There is no
  default.
* **First due date.** An ISO date after ``from``, ``starting``, ``beginning`` or ``on``, or a day of the month ("on
  the 1st"). With none, the rules file decides (``unstated_start``): one period after now, or ``ask``.

Numbers may be digits or words up to ninety-nine ("twenty-four", "twenty four"). A run of number words that does not
form one number makes the term unreadable rather than being read in part.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import Field

from agentvax.resources import load_model
from agentvax.types import ScheduleTerms, Strict

_RULES_PATH = "data/schedule_rules.json"
_UNREADABLE = "#"
"""Stands in for a run of number words that is not one number, so that no pattern reads part of it."""


class ScheduleRules(Strict):
    units: dict[str, Annotated[int, Field(gt=0)]]
    adverbs: dict[str, str]
    unit_words: dict[str, Annotated[int, Field(ge=0, le=19)]]
    tens_words: dict[str, Annotated[int, Field(ge=20, le=90)]]
    count_nouns: tuple[str, ...]
    recurrence_phrases: tuple[str, ...]
    adverb_not_before: tuple[str, ...]
    """Nouns an adverb such as "daily" can describe without a repeat being asked for ("daily limit")."""
    max_day_of_month: Annotated[int, Field(ge=1, le=28)]
    unstated_start: Literal["one_period_after_now", "ask"]


class ScheduleProblem(StrEnum):
    PERIOD = "period"
    RUNS = "runs"
    START = "start"


class ScheduleReading(Strict):
    """What the instruction says about a recurring payment. ``terms`` is set exactly when ``problem`` is None and
    the instruction speaks of a recurring payment."""

    recurring: bool
    terms: ScheduleTerms | None
    problem: ScheduleProblem | None


def load_rules() -> ScheduleRules:
    return load_model(ScheduleRules, _RULES_PATH)


def _numbers_as_digits(text: str, rules: ScheduleRules) -> str:
    """``text`` in lower case with every run of number words written in digits."""
    words = {**rules.unit_words, **rules.tens_words}
    word = "(?:" + "|".join(re.escape(w) for w in sorted(words, key=len, reverse=True)) + ")"
    run = re.compile(rf"\b{word}(?:[\s-]+{word})*\b")

    def digits(match: re.Match[str]) -> str:
        values = [words[w] for w in re.split(r"[\s-]+", match.group(0))]
        if len(values) == 1:
            return str(values[0])
        if len(values) == 2 and values[0] in rules.tens_words.values() and 1 <= values[1] <= 9:
            return str(values[0] + values[1])
        return _UNREADABLE

    return run.sub(digits, text.lower())


def _adverb_pattern(adverb: str, rules: ScheduleRules) -> str:
    excluded = "|".join(re.escape(n) for n in rules.adverb_not_before)
    return rf"\b{re.escape(adverb)}\b(?!\s+(?:{excluded})\b)"


def mentions_recurrence(text: str, rules: ScheduleRules | None = None) -> bool:
    """True if the instruction speaks of a recurring payment in any way the rules know."""
    rules = rules or load_rules()
    lowered = text.lower()
    if any(re.search(p, lowered) for p in rules.recurrence_phrases):
        return True
    return any(re.search(_adverb_pattern(a, rules), lowered) for a in rules.adverbs)


def _next_day_of_month(now: int, day: int) -> int:
    """00:00 UTC on ``day`` of the first month in which that moment is strictly after ``now``."""
    moment = datetime.fromtimestamp(now, tz=timezone.utc)
    candidate = moment.replace(day=day, hour=0, minute=0, second=0, microsecond=0)
    if candidate.timestamp() <= now:
        year, month = (moment.year + 1, 1) if moment.month == 12 else (moment.year, moment.month + 1)
        candidate = candidate.replace(year=year, month=month)
    return int(candidate.timestamp())


def read_schedule(text: str, now: int, rules: ScheduleRules | None = None) -> ScheduleReading:
    """The schedule terms ``text`` states, read at chain time ``now``."""
    rules = rules or load_rules()
    if not mentions_recurrence(text, rules):
        return ScheduleReading(recurring=False, terms=None, problem=None)
    normal = _numbers_as_digits(text, rules)
    unit = "(" + "|".join(re.escape(u) for u in rules.units) + ")s?"

    periods: set[int] = set()
    for match in re.finditer(rf"\b(?:every|each)\s+(?:(\d+)\s+)?{unit}\b", normal):
        count = int(match.group(1)) if match.group(1) else 1
        periods.add(count * rules.units[match.group(2)])
    for adverb, unit_name in rules.adverbs.items():
        if re.search(_adverb_pattern(adverb, rules), normal):
            periods.add(rules.units[unit_name])
    if len(periods) != 1 or 0 in periods:
        return ScheduleReading(recurring=True, terms=None, problem=ScheduleProblem.PERIOD)
    period = periods.pop()

    runs: set[int] = set()
    nouns = "|".join(re.escape(n) for n in rules.count_nouns)
    for match in re.finditer(rf"\b(\d+)\s+(?:{nouns})\b", normal):
        runs.add(int(match.group(1)))
    for match in re.finditer(rf"\bfor\s+(?:the\s+(?:next\s+|coming\s+)?)?(?:(\d+|a|an)\s+)?{unit}\b", normal):
        count = 1 if match.group(1) in (None, "a", "an") else int(match.group(1))
        duration = count * rules.units[match.group(2)]
        if duration % period != 0:
            return ScheduleReading(recurring=True, terms=None, problem=ScheduleProblem.RUNS)
        runs.add(duration // period)
    if _UNREADABLE in normal or len(runs) != 1 or 0 in runs:
        return ScheduleReading(recurring=True, terms=None, problem=ScheduleProblem.RUNS)
    max_runs = runs.pop()

    starts: set[int] = set()
    for match in re.finditer(r"\b(?:from|starting|beginning|on)\s+(\d{4})-(\d{2})-(\d{2})\b", normal):
        try:
            moment = datetime(int(match.group(1)), int(match.group(2)), int(match.group(3)), tzinfo=timezone.utc)
        except ValueError:
            return ScheduleReading(recurring=True, terms=None, problem=ScheduleProblem.START)
        starts.add(int(moment.timestamp()))
    for match in re.finditer(r"\bon the (\d{1,2})(?:st|nd|rd|th)\b", normal):
        day = int(match.group(1))
        if not 1 <= day <= rules.max_day_of_month:
            return ScheduleReading(recurring=True, terms=None, problem=ScheduleProblem.START)
        starts.add(_next_day_of_month(now, day))
    if len(starts) > 1 or any(s <= now for s in starts):
        return ScheduleReading(recurring=True, terms=None, problem=ScheduleProblem.START)
    if starts:
        first_due = starts.pop()
    elif rules.unstated_start == "one_period_after_now":
        first_due = now + period
    else:
        return ScheduleReading(recurring=True, terms=None, problem=ScheduleProblem.START)
    return ScheduleReading(
        recurring=True, terms=ScheduleTerms(period=period, first_due=first_due, max_runs=max_runs), problem=None
    )
