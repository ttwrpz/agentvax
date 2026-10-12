"""Reworded forms of attacks.

Mock mode uses the fixed paraphrases in the attack suite. Live mode asks the model for fresh forms and returns each
exactly as given, unfiltered, as a ledger record.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field

from agentvax.eval.suites_schema import AttackCase
from agentvax.llm.base import LanguageModel, LLMError, Message, MessageRole, Role
from agentvax.llm.prompts import system_prompt
from agentvax.types import Strict
from agentvax.vaxlab.inputs import labels_in

FormKind = Literal["base", "fixed", "generated"]


class AttackForm(Strict):
    """One form of an attack's content, before its placeholders are rendered."""

    base_id: str
    form_id: str
    kind: FormKind
    text: str
    placeholders_kept: bool
    """True if every address placeholder of the base text appears in this form."""


class RewordRequest(Strict):
    """What the rewriter model is shown."""

    attack_text: str
    channel: str
    variant: Annotated[int, Field(ge=1)]


class Rewording(Strict):
    """What the rewriter model returns."""

    text: Annotated[str, Field(min_length=1, max_length=20_000)]


class GeneratedFormRecord(Strict):
    """A generated form as persisted in the ledger, or the failure to generate it."""

    record: Literal["generated_form"] = "generated_form"
    base_id: str
    form_id: str
    variant: int
    status: Literal["generated", "model_failed"]
    text: str | None
    placeholders_kept: bool | None


def _kept(base: str, text: str) -> bool:
    return set(labels_in(base)) <= set(labels_in(text))


def base_form(case: AttackCase) -> AttackForm:
    return AttackForm(base_id=case.id, form_id=case.id, kind="base", text=case.attack.text, placeholders_kept=True)


def fixed_forms(case: AttackCase) -> tuple[AttackForm, ...]:
    """The fixed paraphrases of ``case``, in file order."""
    return tuple(
        AttackForm(
            base_id=case.id, form_id=p.id, kind="fixed", text=p.text, placeholders_kept=_kept(case.attack.text, p.text)
        )
        for p in case.paraphrases
    )


class ModelRewriter:
    """Asks a language model for fresh rewordings. Holds no key and sends nothing on chain."""

    def __init__(self, llm: LanguageModel) -> None:
        self._llm = llm

    def forms(self, case: AttackCase, count: int) -> tuple[tuple[AttackForm, ...], tuple[GeneratedFormRecord, ...]]:
        """``count`` generated forms of ``case`` and a record for every attempt. A model failure is recorded and
        produces no form, so it lowers the number of reworded attacks instead of being replaced."""
        forms: list[AttackForm] = []
        records: list[GeneratedFormRecord] = []
        for variant in range(1, count + 1):
            form_id = f"{case.id}.generated{variant}"
            request = RewordRequest(attack_text=case.attack.text, channel=case.attack.channel, variant=variant)
            messages = [
                Message(role=MessageRole.SYSTEM, content=system_prompt(Role.REWRITER)),
                Message(role=MessageRole.USER, content=request.model_dump_json()),
            ]
            try:
                reply = self._llm.complete(Role.REWRITER, messages, Rewording)
            except LLMError:
                records.append(
                    GeneratedFormRecord(
                        base_id=case.id,
                        form_id=form_id,
                        variant=variant,
                        status="model_failed",
                        text=None,
                        placeholders_kept=None,
                    )
                )
                continue
            kept = _kept(case.attack.text, reply.text)
            forms.append(
                AttackForm(base_id=case.id, form_id=form_id, kind="generated", text=reply.text, placeholders_kept=kept)
            )
            records.append(
                GeneratedFormRecord(
                    base_id=case.id,
                    form_id=form_id,
                    variant=variant,
                    status="generated",
                    text=reply.text,
                    placeholders_kept=kept,
                )
            )
        return tuple(forms), tuple(records)
