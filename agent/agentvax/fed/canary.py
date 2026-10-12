"""The canary check a wallet runs before it adopts a model.

A text is caught when it falls in band MEDIUM or HIGH. A candidate is rejected if canary recall drops or the
false-positive rate rises by more than the tolerance, compared with the current model.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

from agentvax.detector.model import Detector, DetectorModel
from agentvax.fed.config import CanaryTolerance
from agentvax.fed.data import CanarySet
from agentvax.types import Band

Rate = Annotated[float, Field(ge=0.0, le=1.0)]


class CanaryScore(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, allow_inf_nan=False)

    recall: Rate
    false_positive_rate: Rate


class CanaryVerdict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, allow_inf_nan=False)

    current: CanaryScore
    candidate: CanaryScore
    accepted: bool


def caught(detector: Detector, text: str) -> bool:
    """Whether the detector flags ``text``: band MEDIUM or HIGH."""
    return detector.band(text) >= Band.MEDIUM


def detection_rate(detector: Detector, texts: tuple[str, ...] | list[str]) -> float:
    """Fraction of ``texts`` the detector flags. Zero for no texts."""
    if not texts:
        return 0.0
    return sum(1 for t in texts if caught(detector, t)) / len(texts)


def score(model: DetectorModel, canary: CanarySet) -> CanaryScore:
    detector = Detector(model)
    return CanaryScore(
        recall=detection_rate(detector, canary.attack),
        false_positive_rate=detection_rate(detector, canary.benign),
    )


def judge(current: CanaryScore, candidate: CanaryScore, tolerance: CanaryTolerance) -> bool:
    """True if the candidate is acceptable: recall not lower by more than the tolerance and false-positive rate
    not higher by more than the tolerance."""
    recall_drop = current.recall - candidate.recall
    fpr_rise = candidate.false_positive_rate - current.false_positive_rate
    return recall_drop <= tolerance.max_recall_drop and fpr_rise <= tolerance.max_fpr_rise


def check(
    current: DetectorModel, candidate: DetectorModel, canary: CanarySet, tolerance: CanaryTolerance
) -> CanaryVerdict:
    now = score(current, canary)
    then = score(candidate, canary)
    return CanaryVerdict(current=now, candidate=then, accepted=judge(now, then, tolerance))
