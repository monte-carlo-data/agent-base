import re
from typing import Any, List, Dict, Tuple

from apollo.common.agent.constants import (
    ATTRIBUTE_VALUE_REDACTED,
    LOG_ATTRIBUTE_TRACE_ID,
)

_STANDARD_REDACTED_ATTRIBUTES = [
    "pass",
    "secret",
    "client",
    "token",
    "user",
    "auth",
    "credential",
    "key",
]
_REDACT_VALUE_EXPRESSIONS = [
    re.compile(r"[a-zA-Z0-9_\-+=]{32,64}"),  # trying to match tokens and API keys
    re.compile(r"password", re.IGNORECASE),
    re.compile(r"secret", re.IGNORECASE),
    re.compile(r"token", re.IGNORECASE),
    re.compile(r"key", re.IGNORECASE),
    re.compile(r"auth", re.IGNORECASE),
    re.compile(r"credential", re.IGNORECASE),
]
_SKIP_REDACT_ATTRIBUTES = [LOG_ATTRIBUTE_TRACE_ID, "agent_id", "uuid"]

# Sensitive key names whose *value* must be stripped when it appears in a
# "key=value" / "key: value" connect string, DSN, or header (the form used by
# libpq, JDBC/ODBC, SQLAlchemy, etc.). Matched as whole words only.
_SENSITIVE_VALUE_KEY = (
    r"password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|secret[_-]?key"
    r"|private[_-]?key|client[_-]?secret|credentials?|authorization|auth"
    r"|user(?:name)?|uid"
)
# Inline patterns that strip secret *values* out of free-form text (error
# messages, exception strings, traceback frames) while leaving the surrounding
# text intact, so the error stays actionable. Unlike `_redact_string`, which
# replaces the entire matching string, these replace only the captured secret.
_REDACT_INLINE_EXPRESSIONS = [
    # URL userinfo, e.g. postgresql://admin:hunter2@host/db -> ...://__redacted__@host/db
    (
        re.compile(r"(?P<scheme>[a-zA-Z][a-zA-Z0-9+.\-]*://)[^/?#\s@]+@"),
        rf"\g<scheme>{ATTRIBUTE_VALUE_REDACTED}@",
    ),
    # Authorization headers, e.g. "Bearer <token>" / "Basic <base64>"
    (
        re.compile(
            r"(?P<scheme>\b(?:bearer|basic))(?P<sep>\s+)[A-Za-z0-9_\-.=+/]{8,}",
            re.IGNORECASE,
        ),
        rf"\g<scheme>\g<sep>{ATTRIBUTE_VALUE_REDACTED}",
    ),
    # key=value / key: value pairs for sensitive keys (connect strings, DSNs,
    # and quoted JSON like {"password": "..."}). The separator tolerates a
    # closing quote on the key so JSON blobs embedded in error text are covered.
    (
        re.compile(
            rf"(?P<key>\b(?:{_SENSITIVE_VALUE_KEY}))(?P<sep>[\"']?\s*[:=]\s*)"
            r"(?P<quote>[\"']?)[^\"'\s;,&]+(?P=quote)",
            re.IGNORECASE,
        ),
        rf"\g<key>\g<sep>{ATTRIBUTE_VALUE_REDACTED}",
    ),
    # bare high-entropy tokens (contiguous 32+ alnum/underscore runs); the word
    # boundaries and lack of separators keep hostnames and UUIDs from matching
    (re.compile(r"\b[A-Za-z0-9_]{32,}\b"), ATTRIBUTE_VALUE_REDACTED),
]


class AgentRedactUtilities:
    @classmethod
    def standard_redact(cls, value: Any):
        return cls.redact_attributes(value, _STANDARD_REDACTED_ATTRIBUTES)

    @classmethod
    def redact_sensitive_text(cls, value: Any) -> Any:
        """
        Strip secret *values* out of free-form text while preserving the
        surrounding message, so error responses sent to the SaaS stay actionable
        without leaking credentials embedded in connect strings, DSNs, or headers.

        Recurses through lists/tuples (e.g. a traceback rendered as a list of
        frame strings); non-string scalars are returned unchanged.
        """
        if isinstance(value, str):
            for expression, replacement in _REDACT_INLINE_EXPRESSIONS:
                value = expression.sub(replacement, value)
            return value
        elif isinstance(value, List):
            return [cls.redact_sensitive_text(v) for v in value]
        elif isinstance(value, Tuple):
            return tuple(cls.redact_sensitive_text(v) for v in value)
        else:
            return value

    @classmethod
    def redact_attributes(cls, value: Any, attributes: List[str]) -> Any:
        if isinstance(value, Dict):
            return {
                k: (
                    ATTRIBUTE_VALUE_REDACTED
                    if cls._is_attribute_included(k, attributes)
                    else (
                        v
                        if cls._is_attribute_included(k, _SKIP_REDACT_ATTRIBUTES, True)
                        else cls.redact_attributes(v, attributes)
                    )
                )
                for k, v in value.items()
            }
        elif isinstance(value, List):
            return [cls.redact_attributes(v, attributes) for v in value]
        elif isinstance(value, Tuple):
            return tuple(cls.redact_attributes(v, attributes) for v in value)
        elif isinstance(value, str):
            return cls._redact_string(value)
        else:
            return value

    @staticmethod
    def _is_attribute_included(
        key: str, attributes: List[str], exact_match: bool = False
    ) -> bool:
        return (
            key in attributes
            if exact_match
            else any(a in key.lower() for a in attributes)
        )

    @staticmethod
    def _redact_string(value: str) -> str:
        for expression in _REDACT_VALUE_EXPRESSIONS:
            if expression.search(value):
                return ATTRIBUTE_VALUE_REDACTED
        return value
