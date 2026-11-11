"""Privacy and input-safety helpers for the Keystone mortgage agent."""

import base64
import binascii
import re
import secrets
import threading
from typing import Any

from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig


class ContentFilterMiddleware:
    """Detect common prompt-injection attempts before sending text to an LLM."""

    MAX_INPUT_LENGTH = 32_768
    MAX_DECODED_LENGTH = 8_192
    MAX_BASE64_CANDIDATES = 32
    MAX_BASE64_LAYERS = 2
    BASE64_CANDIDATE = re.compile(
        r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{20,}={0,2}(?![A-Za-z0-9+/_=-])"
    )
    ATTACK_VAULT = (
        r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|rules|prompts)",
        r"disregard\s+(all\s+)?(rules|limits|instructions)",
        r"(system\s+prompt|what\s+are\s+your\s+rules)",
        r"bypass\s+(underwriter|check|policy|limit|rules|affordability|mandate)",
        r"override\s+(credit|affordability|decision|limit|underwriting|mandate)",
        r"grant\s+vip\s+(waiver|exception|override)",
        r"\bjailbreak\b",
        r"\bact\s+as\s+dan\b",
        r"auto[- ]approve\s+me",
        r"force\s+(approval|dip|decision)",
        r"(export|dump|reveal|print|list)\s+(all\s+)?(applicant|customer|mortgage)\s+"
        r"(records|profiles|data|files|applications)",
    )
    INJECTION_PATTERNS = ATTACK_VAULT

    @classmethod
    def inspect_input(cls, text: str) -> tuple[bool, str, float]:
        if not isinstance(text, str):
            raise TypeError("Input safety inspection requires text.")
        if len(text) > cls.MAX_INPUT_LENGTH:
            return False, "Input exceeds the safety inspection limit.", 1.0
        risk_score = 0.0

        candidates = [("original", text)]
        frontier = [text]
        seen_decoded = set()
        decoded_count = 0
        for _ in range(cls.MAX_BASE64_LAYERS):
            next_frontier = []
            for candidate_text in frontier:
                for encoded in cls.BASE64_CANDIDATE.findall(candidate_text):
                    if decoded_count >= cls.MAX_BASE64_CANDIDATES:
                        return False, "Input exceeds the encoded-content inspection limit.", 1.0
                    decoded_count += 1
                    normalized = encoded.replace("-", "+").replace("_", "/")
                    normalized += "=" * (-len(normalized) % 4)
                    try:
                        decoded_bytes = base64.b64decode(normalized, validate=True)
                        if len(decoded_bytes) > cls.MAX_DECODED_LENGTH:
                            return False, "Encoded content exceeds the safety inspection limit.", 1.0
                        decoded_variants = []
                        try:
                            decoded_variants.append(decoded_bytes.decode("utf-8-sig"))
                        except UnicodeDecodeError:
                            pass
                        if decoded_bytes.startswith((b"\xff\xfe", b"\xfe\xff")) or b"\x00" in decoded_bytes:
                            try:
                                decoded_variants.append(decoded_bytes.decode("utf-16"))
                            except UnicodeDecodeError:
                                pass
                    except (binascii.Error, UnicodeDecodeError, ValueError):
                        continue
                    for decoded in decoded_variants:
                        if decoded and decoded not in seen_decoded:
                            seen_decoded.add(decoded)
                            candidates.append(("decoded", decoded))
                            next_frontier.append(decoded)
            frontier = next_frontier
            if not frontier or decoded_count >= cls.MAX_BASE64_CANDIDATES:
                break
        if any(cls.BASE64_CANDIDATE.search(candidate) for candidate in frontier):
            return False, "Nested encoded content exceeds the safety inspection depth.", 1.0

        decoded_match = False
        for candidate_source, candidate_text in candidates:
            for pattern in cls.ATTACK_VAULT:
                if re.search(pattern, candidate_text, flags=re.IGNORECASE):
                    if candidate_source == "decoded":
                        decoded_match = True
                    else:
                        return False, "Prompt-injection pattern detected.", 0.7
        if decoded_match:
            return False, "Encoded prompt-injection pattern detected.", 0.7
        return True, "CLEAN", risk_score


class LocalRebuffGuard:
    """Local Rebuff-compatible pre-check and canary detector.

    The implementation deliberately does not send prompts to an external
    Rebuff service; detection uses the local mortgage attack vault above.
    """

    def __init__(self) -> None:
        self._canary_words: set[str] = set()

    def detect_injection(self, user_input: str) -> bool:
        allowed, _, _ = ContentFilterMiddleware.inspect_input(user_input)
        return not allowed

    def add_canary_word(self, canary_word: str) -> None:
        if not isinstance(canary_word, str) or not canary_word:
            raise ValueError("A non-empty canary word is required.")
        self._canary_words.add(canary_word)

    def is_canary_word_leaked(self, output: str) -> bool:
        if not isinstance(output, str):
            raise TypeError("Canary inspection requires text.")
        return any(canary in output for canary in self._canary_words)


def create_prompt_canary() -> str:
    """Create an unpredictable, process-local marker for system-prompt leakage checks."""
    return f"KEYSTONE-CANARY-{secrets.token_urlsafe(24)}"


class PIISanitizationMiddleware:
    """Use local Presidio detection and anonymization for model-bound text."""

    _analyzer: AnalyzerEngine | None = None
    _anonymizer: AnonymizerEngine | None = None
    _engine_lock = threading.Lock()
    _REDACT_OPERATORS = {
        "DEFAULT": OperatorConfig("replace", {"new_value": "[REDACTED]"})
    }
    SENSITIVE_KEYS = {
        "account_number",
        "national_insurance_number",
        "national_id",
        "sort_code",
        "date_of_birth",
        "birth_date",
        "dob",
        "postcode",
        "postal_code",
        "address",
        "residential_address",
        "email",
        "phone",
        "phone_number",
        "mobile",
        "mobile_number",
        "telephone",
        "applicant_name",
        "customer_name",
        "queried_name",
        "first_name",
        "last_name",
        "full_name",
    }

    @classmethod
    def _get_engines(cls) -> tuple[AnalyzerEngine, AnonymizerEngine]:
        if cls._analyzer is not None and cls._anonymizer is not None:
            return cls._analyzer, cls._anonymizer

        with cls._engine_lock:
            if cls._analyzer is not None and cls._anonymizer is not None:
                return cls._analyzer, cls._anonymizer
            try:
                nlp_engine = NlpEngineProvider(
                    nlp_configuration={
                        "nlp_engine_name": "spacy",
                        "models": [
                            {
                                "lang_code": "en",
                                "model_name": "en_core_web_sm",
                            }
                        ],
                    }
                ).create_engine()
                analyzer = AnalyzerEngine(
                    nlp_engine=nlp_engine,
                    supported_languages=["en"],
                )
                analyzer.registry.add_recognizer(
                    PatternRecognizer(
                        supported_entity="UK_NATIONAL_INSURANCE_NUMBER",
                        patterns=[
                            Pattern(
                                name="uk_national_insurance_number",
                                regex=r"\b[A-Z]{2}[\s-]?\d{2}[\s-]?\d{2}[\s-]?\d{2}[\s-]?[A-Z]\b",
                                score=0.9,
                            )
                        ],
                        supported_language="en",
                    )
                )
                analyzer.registry.add_recognizer(
                    PatternRecognizer(
                        supported_entity="UK_SORT_CODE",
                        patterns=[
                            Pattern(
                                name="uk_sort_code",
                                regex=r"\b\d{2}[- ]\d{2}[- ]\d{2}\b",
                                score=0.85,
                            )
                        ],
                        context=["sort code", "bank details"],
                        supported_language="en",
                    )
                )
                analyzer.registry.add_recognizer(
                    PatternRecognizer(
                        supported_entity="UK_BANK_ACCOUNT_NUMBER",
                        patterns=[
                            Pattern(
                                name="uk_bank_account_number",
                                regex=r"\b\d{8}\b",
                                score=0.8,
                            )
                        ],
                        context=["account", "account number", "bank details"],
                        supported_language="en",
                    )
                )
                analyzer.registry.add_recognizer(
                    PatternRecognizer(
                        supported_entity="UK_POSTCODE",
                        patterns=[
                            Pattern(
                                name="uk_postcode",
                                regex=r"\b(?:GIR\s?0AA|[A-Z]{1,2}\d[A-Z\d]?\s*\d[A-Z]{2})\b",
                                score=0.85,
                            )
                        ],
                        supported_language="en",
                    )
                )
                cls._analyzer = analyzer
                cls._anonymizer = AnonymizerEngine()
            except Exception as exc:
                raise RuntimeError(
                    "Presidio PII protection could not initialize. Install the "
                    "declared dependencies and the en_core_web_sm spaCy model."
                ) from exc

        return cls._analyzer, cls._anonymizer

    @classmethod
    def sanitize_with_metadata(cls, text: str) -> tuple[str, list[str]]:
        if not isinstance(text, str):
            raise TypeError("PII sanitization requires text input.")
        if not text:
            return text, []

        analyzer, anonymizer = cls._get_engines()
        findings = analyzer.analyze(text=text, language="en")
        sanitized = anonymizer.anonymize(
            text=text,
            analyzer_results=findings,
            operators=cls._REDACT_OPERATORS,
        ).text
        detected_entities = sorted({finding.entity_type for finding in findings})
        return sanitized, detected_entities

    @classmethod
    def sanitize_for_llm(cls, text: str) -> str:
        sanitized, _ = cls.sanitize_with_metadata(text)
        return sanitized

    @classmethod
    def redact_sensitive_value(cls, value: Any, key: str = "") -> Any:
        if key.lower() in cls.SENSITIVE_KEYS:
            return "[REDACTED]"
        if isinstance(value, dict):
            return {
                item_key: cls.redact_sensitive_value(item_value, str(item_key))
                for item_key, item_value in value.items()
            }
        if isinstance(value, list):
            return [cls.redact_sensitive_value(item) for item in value]
        if isinstance(value, tuple):
            return tuple(cls.redact_sensitive_value(item) for item in value)
        if isinstance(value, str):
            return cls.sanitize_for_llm(value)
        return value
