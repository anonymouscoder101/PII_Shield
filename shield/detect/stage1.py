"""Local English Presidio/spaCy candidate detection, before policy resolution.

Loading is explicit and never downloads a model. Results contain coordinates,
types and scores only. analyze() applies the shared threshold/allowlist/overlap
policy while detect() retains candidate access for evaluation.
"""

import logging
from contextvars import ContextVar
from importlib.metadata import version
from threading import Lock

import regex
import spacy
from presidio_analyzer import (
    Pattern,
    PatternRecognizer,
    RecognizerRegistry,
)
from presidio_analyzer.nlp_engine import NerModelConfiguration, SpacyNlpEngine
from presidio_analyzer.predefined_recognizers import (
    CreditCardRecognizer,
    EmailRecognizer,
    IpRecognizer,
    PhoneRecognizer,
    SpacyRecognizer,
    UsSsnRecognizer,
)
from spacy.language import Language

from shield.config import DetectionConfig
from shield.contracts import DetectedSpan, EntityType
from shield.detect.candidates import CandidateAnalyzer
from shield.detect.recognizers import (
    ApiKeyRecognizer,
    DateOfBirthRecognizer,
    SecretRecognizer,
    employee_id_recognizer,
)
from shield.detect.resolve import ResolvedDetections, SpanPolicy

MODEL_NAME = "en_core_web_lg"
MODEL_VERSION = "3.8.0"
STAGE1_ENTITIES = (
    EntityType.PERSON,
    EntityType.EMAIL_ADDRESS,
    EntityType.PHONE_NUMBER,
    EntityType.CREDIT_CARD,
    EntityType.US_SSN,
    EntityType.LOCATION,
    EntityType.ADDRESS,
    EntityType.IP_ADDRESS,
    EntityType.DATE_OF_BIRTH,
    EntityType.API_KEY,
    EntityType.SECRET,
    EntityType.EMPLOYEE_ID,
)
_NER_MAPPING = {
    "PERSON": "PERSON",
    "GPE": "LOCATION",
    "LOC": "LOCATION",
    "FAC": "LOCATION",
}
_scanning: ContextVar[bool] = ContextVar("shield_stage1_scanning", default=False)


class _PrivatePresidioLogs(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        # Presidio context-enhancer DEBUG logs contain source words. Filtering
        # at the source logger protects every handler without changing log levels
        # globally or interfering with unrelated threads/contexts.
        return not _scanning.get()


logging.getLogger("presidio-analyzer").addFilter(_PrivatePresidioLogs())


class DetectorUnavailable(ValueError):
    """Static startup/configuration failure, without paths or library exceptions."""


class Stage1DetectionError(ValueError):
    """Static runtime failure, without input or recognizer exception text."""


class _StrictRegex:
    """Presidio catches bare TimeoutError and skips the pattern; abort instead."""

    def __init__(self, compiled):
        self._compiled = compiled

    def finditer(self, *args, **kwargs):
        try:
            for match in self._compiled.finditer(*args, **kwargs):
                start, end = match.span()
                if end <= start:
                    raise Stage1DetectionError("Stage 1 detection failed.")
                yield match
        except TimeoutError:
            raise Stage1DetectionError("Stage 1 detection failed.") from None


class Stage1Detector:
    """Validated registry backed by an explicitly loaded English spaCy pipeline.

    One instance serializes calls because its NLP pipeline and recognizers are
    mutable. Run detection off the event loop when wiring the gateway later.
    Registry availability is capability metadata, not a recall guarantee.
    """

    def __init__(self, nlp: Language, config: DetectionConfig | None = None):
        self.config = config if config is not None else DetectionConfig()
        self.entities = tuple(
            entity
            for entity in STAGE1_ENTITIES
            if not (
                (
                    entity == EntityType.LOCATION
                    and self.config.location_policy == "none"
                )
                or (
                    entity == EntityType.ADDRESS
                    and self.config.address_policy == "none"
                )
                or (
                    entity == EntityType.EMPLOYEE_ID
                    and not self.config.employee_id_enabled
                )
            )
        )
        mapping = {
            label: entity
            for label, entity in _NER_MAPPING.items()
            if label == "PERSON"
            or (
                self.config.location_policy != "none"
                and (label != "FAC" or self.config.location_policy == "all")
            )
        }
        try:
            self.policy = SpanPolicy(self.config)
            if nlp.lang != "en" or "ner" not in nlp.pipe_names:
                raise ValueError("English NER required")
            labels = set(nlp.get_pipe("ner").labels)
            if not set(mapping) <= labels:
                raise ValueError("required NER labels missing")
            self.ner_labels = tuple(sorted(labels))
            self.model_name = f"{nlp.lang}_{nlp.meta.get('name', 'pipeline')}"
            self.model_version = nlp.meta.get("version", "")
            engine = SpacyNlpEngine(
                models=[{"lang_code": "en", "model_name": MODEL_NAME}],
                ner_model_configuration=NerModelConfiguration(
                    model_to_presidio_entity_mapping=mapping,
                    labels_to_ignore=sorted(labels - set(mapping)),
                    default_score=0.85,
                ),
            )
            # Already loaded: avoids Presidio's automatic model download path.
            engine.nlp = {"en": nlp}
            recognizers = [
                SpacyRecognizer(supported_entities=sorted(set(mapping.values()))),
                # Reuse upstream email patterns without network-dependent public
                # suffix validation. Internal/synthetic dotted domains are valid.
                PatternRecognizer(
                    supported_entity="EMAIL_ADDRESS",
                    patterns=EmailRecognizer.PATTERNS,
                    context=EmailRecognizer.CONTEXT,
                    name="ShieldEmailRecognizer",
                ),
                PhoneRecognizer(supported_regions=self.config.phone_regions.copy()),
                CreditCardRecognizer(),
                UsSsnRecognizer(),
                IpRecognizer(),
                PatternRecognizer(
                    supported_entity="ADDRESS",
                    name="ShieldStreetAddressRecognizer",
                    patterns=[
                        Pattern(
                            "Numbered English street address",
                            r"\b\d{1,6}[ \t]+(?:[A-Za-z][A-Za-z\x27.-]*[ \t]+){1,6}"
                            r"(?:Street|St|Road|Rd|Avenue|Ave|Lane|Ln|Drive|Dr|Boulevard|Blvd|Court|Ct|Way)\b",
                            0.6,
                        )
                    ],
                ),
            ]
            recognizers.extend(
                [DateOfBirthRecognizer(), ApiKeyRecognizer(), SecretRecognizer()]
            )
            if self.config.employee_id_enabled:
                recognizers.append(
                    employee_id_recognizer(self.config.employee_id_pattern)
                )
            if self.config.address_policy == "none":
                recognizers = [
                    rec
                    for rec in recognizers
                    if "ADDRESS" not in rec.supported_entities
                ]
            for recognizer in recognizers:
                if isinstance(recognizer, PatternRecognizer):
                    # Pattern instances on built-ins can be class-level mutable
                    # objects. Clone before adding per-detector compiled state.
                    recognizer.patterns = [
                        Pattern(p.name, p.regex, p.score) for p in recognizer.patterns
                    ]
                    for pattern in recognizer.patterns:
                        pattern.compiled_with_flags = recognizer.global_regex_flags
                        pattern.compiled_regex = _StrictRegex(
                            regex.compile(pattern.regex, recognizer.global_regex_flags)
                        )
            registry = RecognizerRegistry(
                recognizers=recognizers, supported_languages=["en"]
            )
            self._analyzer = CandidateAnalyzer(
                nlp_engine=engine,
                registry=registry,
                supported_languages=["en"],
                log_decision_process=False,
                default_score_threshold=0,
            )
            available = set(self._analyzer.get_supported_entities(language="en"))
            if not {entity.value for entity in self.entities} <= available:
                raise ValueError("required recognizer unavailable")
            self.capabilities = {
                entity: tuple(
                    sorted(
                        rec.name
                        for rec in registry.recognizers
                        if entity.value in rec.supported_entities
                    )
                )
                for entity in self.entities
            }
            if not all(self.capabilities.values()):
                raise ValueError("required recognizer unavailable")
            self._lock = Lock()
        except Exception:
            raise DetectorUnavailable("Stage 1 recognizers are unavailable.") from None

    @classmethod
    def load(cls, config: DetectionConfig | None = None) -> Stage1Detector:
        try:
            if version(MODEL_NAME) != MODEL_VERSION:
                raise ValueError("unsupported model version")
            nlp = spacy.load(MODEL_NAME, exclude=["parser"])
            return cls(nlp, config=config)
        except Exception:
            raise DetectorUnavailable(
                "Stage 1 model is unavailable; install the pinned stage1 extra."
            ) from None

    def detect(self, text: str) -> list[DetectedSpan]:
        if not isinstance(text, str):
            raise Stage1DetectionError("Stage 1 detection failed.")
        if not text:
            return []
        with self._lock:
            token = _scanning.set(True)
            try:
                results = self._analyzer.analyze(
                    text=text,
                    language="en",
                    entities=[entity.value for entity in self.entities],
                    score_threshold=0.0,
                    return_decision_process=False,
                )
                spans = []
                for result in results:
                    entity = EntityType(result.entity_type)
                    if entity not in self.entities:
                        raise ValueError("unsupported detector result")
                    spans.append(
                        DetectedSpan(
                            start=result.start,
                            end=result.end,
                            entity_type=entity,
                            confidence=result.score,
                        ).validate_for_text(text)
                    )
                return sorted(
                    spans,
                    key=lambda span: (
                        span.start,
                        span.end,
                        span.entity_type.value,
                        -span.confidence,
                    ),
                )
            except Exception:
                raise Stage1DetectionError("Stage 1 detection failed.") from None
            finally:
                _scanning.reset(token)

    def analyze(self, text: str) -> ResolvedDetections:
        """Detect then apply the shared policy snapshot to original coordinates."""
        return self.policy.resolve(text, self.detect(text))
