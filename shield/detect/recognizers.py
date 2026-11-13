"""Local custom recognizers. Returned matches contain values, never field labels."""

from datetime import date

from presidio_analyzer import Pattern, PatternRecognizer


def _assignment(labels: str) -> str:
    return rf"""\b(?:{labels})["']?[ \t]*[:=][ \t]*"""


def _assigned_patterns(labels: str) -> list[Pattern]:
    prefix = _assignment(labels)
    return [
        Pattern(
            "Double-quoted assigned value",
            prefix + r'"\K(?:\\[^\r\n]|[^"\\\r\n])+(?=")',
            0.85,
        ),
        Pattern(
            "Single-quoted assigned value",
            prefix + r"'\K(?:\\[^\r\n]|[^'\\\r\n])+(?=')",
            0.85,
        ),
        Pattern(
            "Backtick-quoted assigned value",
            prefix + r"`\K[^`\r\n]+(?=`)",
            0.85,
        ),
        Pattern(
            "Unquoted assigned value",
            prefix + r"""(?!["'`])\K\S+""",
            0.85,
        ),
    ]


class DateOfBirthRecognizer(PatternRecognizer):
    def __init__(self):
        prefix = (
            r"\b(?:dob|date[ \t]+of[ \t]+birth|birth[ \t]*date|born(?:[ \t]+on)?)"
            r"""["']?(?:[ \t]*[:=][ \t]*|[ \t]+)["']?\K"""
        )
        value = (
            r"(?:\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{4}|"
            r"\d{1,2}[ \t]+[A-Za-z]{3,9}[ \t]+\d{4})(?![\w/-])"
        )
        super().__init__(
            supported_entity="DATE_OF_BIRTH",
            name="ShieldDateOfBirthRecognizer",
            patterns=[Pattern("Labeled calendar birth date", prefix + value, 0.85)],
        )

    def validate_result(self, pattern_text: str) -> bool:
        # Parse English months explicitly; strptime month names depend on the
        # host process locale, which can differ from this English detector.
        try:
            if "-" in pattern_text:
                year, month, day = map(int, pattern_text.split("-"))
                date(year, month, day)
            elif "/" in pattern_text:
                first, second, year = map(int, pattern_text.split("/"))
                try:
                    date(year, first, second)
                except ValueError:
                    date(year, second, first)
            else:
                day, month_name, year = pattern_text.split()
                months = (
                    "january",
                    "february",
                    "march",
                    "april",
                    "may",
                    "june",
                    "july",
                    "august",
                    "september",
                    "october",
                    "november",
                    "december",
                )
                names = {name: index for index, name in enumerate(months, 1)}
                names.update({name[:3]: index for index, name in enumerate(months, 1)})
                date(int(year), names[month_name.lower()], int(day))
            return True
        except ValueError, KeyError:
            return False


class ApiKeyRecognizer(PatternRecognizer):
    def __init__(self):
        patterns = _assigned_patterns(r"api[_ -]?key|access[_ -]?key")
        patterns.append(
            Pattern(
                "Common API-key prefix",
                r"(?<![\w-])(?:sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16})(?![\w-])",
                0.85,
            )
        )
        super().__init__(
            supported_entity="API_KEY", name="ShieldApiKeyRecognizer", patterns=patterns
        )


class SecretRecognizer(PatternRecognizer):
    def __init__(self):
        patterns = _assigned_patterns(
            r"secret|secret[_ -]?key|client[_ -]?secret|api[_ -]?secret|"
            r"password|passwd|"
            r"access[_ -]?token|auth[_ -]?token|aws[_ -]?secret[_ -]?access[_ -]?key"
        )
        patterns.append(
            Pattern(
                "Bearer credential",
                r"\bBearer[ \t]+\K[A-Za-z0-9._~+/-]{8,}={0,2}(?![A-Za-z0-9._~+/-])",
                0.85,
            )
        )
        super().__init__(
            supported_entity="SECRET", name="ShieldSecretRecognizer", patterns=patterns
        )


def employee_id_recognizer(pattern: str) -> PatternRecognizer:
    return PatternRecognizer(
        supported_entity="EMPLOYEE_ID",
        name="ShieldEmployeeIdRecognizer",
        patterns=[Pattern("Configured employee identifier", pattern, 0.85)],
    )
