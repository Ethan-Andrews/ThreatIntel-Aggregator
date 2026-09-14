"""Provider-neutral types for draft-detection generation.

This repo ships a concrete provider (DetectionsAIClient, see
detections_client.py) but the pipeline itself does not require one --
orchestrator.run()'s _build_draft_provider() returns None when no provider
is configured (no DETECTIONS_AI_API_KEY set), and every other pipeline
stage (static gate, control probe, backtest, tune, disposition tracking,
hunt sync, Sentinel-native content) runs independently of whether a draft
provider is present. A future alternative or self-hosted provider can
return these shapes to plug into orchestrator.process_one() the same way
DetectionsAIClient does today.
"""

from __future__ import annotations

from dataclasses import dataclass, field


class DraftProviderError(RuntimeError):
    """Any failure surfaced by a draft-detection provider."""


class SourcePreparationFailed(DraftProviderError):
    """The source content could not be fetched or prepared for drafting."""


class DraftingTimeout(DraftProviderError):
    """A drafting poll loop exhausted its budget without finishing."""


@dataclass
class CoverageItem:
    """One technique-level coverage opportunity returned by a provider."""

    opportunity_title: str
    primary_mitre_attack_id: str
    mitre_attack_ids: list[str]
    data_source: str
    status: str  # covered | gap | unable_to_determine
    matched_rules: list[dict] = field(default_factory=list)

    @property
    def is_gap(self) -> bool:
        return self.status == "gap"


@dataclass
class CoverageReport:
    items: list[CoverageItem]
    summary: dict

    @property
    def gaps(self) -> list[CoverageItem]:
        return [i for i in self.items if i.is_gap]

    @property
    def undetermined(self) -> list[CoverageItem]:
        return [i for i in self.items if i.status == "unable_to_determine"]


@dataclass
class DraftDetection:
    artifact_id: str
    title: str
    description: str
    content: str


@dataclass
class DraftBundle:
    run_id: str
    coverage: CoverageReport
    detections: list[DraftDetection]
    review_url: str | None = None
