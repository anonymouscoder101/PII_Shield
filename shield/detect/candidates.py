"""Preserve recognizer candidates until Shield's confidence and allowlist policy."""

from copy import copy

from presidio_analyzer import AnalyzerEngine, PatternRecognizer, RecognizerResult


class CandidateAnalyzer(AnalyzerEngine):
    """Run audited local recognizers without Presidio containment deduplication.

    Pattern recognizers also deduplicate internally. Analyze singleton pattern
    copies so one pattern's outer result cannot erase another's nested match.
    Copies retain the original recognizer identity for normal context scoring.
    The caller serializes access and strips library metadata into domain spans.
    """

    def analyze(
        self,
        text: str,
        language: str,
        entities: list[str],
        *,
        score_threshold: float = 0.0,
        return_decision_process: bool = False,
    ) -> list[RecognizerResult]:
        if score_threshold != 0 or return_decision_process:
            raise ValueError("candidate analysis requires unfiltered private results")
        recognizers = self.registry.get_recognizers(
            language=language, entities=entities
        )
        artifacts = self.nlp_engine.process_text(text, language)
        results = []
        for recognizer in recognizers:
            if not recognizer.is_loaded:
                recognizer.load()
                recognizer.is_loaded = True
            if isinstance(recognizer, PatternRecognizer):
                analyzers = []
                for pattern in recognizer.patterns:
                    singleton = copy(recognizer)
                    singleton.patterns = [pattern]
                    analyzers.append(singleton)
            else:
                analyzers = [recognizer]
            for analyzer in analyzers:
                found = analyzer.analyze(
                    text=text, entities=entities, nlp_artifacts=artifacts
                )
                for result in found:
                    if result.recognition_metadata is None:
                        result.recognition_metadata = {}
                    result.recognition_metadata[
                        RecognizerResult.RECOGNIZER_IDENTIFIER_KEY
                    ] = recognizer.id
                    result.recognition_metadata[
                        RecognizerResult.RECOGNIZER_NAME_KEY
                    ] = recognizer.name
                results.extend(found)
        # Retain Presidio's recognizer-specific and lemma context enhancement.
        # Its protected hook is covered by integration tests against uv.lock.
        results = self._enhance_using_context(
            text, results, artifacts, recognizers, context=None
        )
        for result in results:
            result.analysis_explanation = None
        return results
