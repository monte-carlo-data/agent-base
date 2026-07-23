from unittest import TestCase

from apollo.common.agent.constants import (
    ATTRIBUTE_NAME_ERROR,
    ATTRIBUTE_NAME_ERROR_ATTRS,
    ATTRIBUTE_NAME_ERROR_TYPE,
    ATTRIBUTE_NAME_EXCEPTION,
    ATTRIBUTE_NAME_STACK_TRACE,
    ATTRIBUTE_VALUE_REDACTED,
)
from apollo.common.agent.utils import AgentUtils

_PASSWORD = "hunter2pwd"
_USER = "admin"


class ErrorResponseRedactionTests(TestCase):
    """Secret *values* must never survive in error responses sent to the SaaS,
    while the surrounding message stays actionable (the redaction is value-level,
    not whole-string)."""

    def test_keyed_connect_string_value_is_stripped_message_stays_actionable(self):
        # libpq / ODBC style connect string embedded in an exception message
        message = (
            f"could not connect: host=db.example.com port=5432 dbname=prod "
            f"user={_USER} password={_PASSWORD}"
        )
        response = AgentUtils._response_for_error(message)
        error = response[ATTRIBUTE_NAME_ERROR]
        self.assertNotIn(_PASSWORD, error)
        self.assertNotIn(f"user={_USER}", error)
        # actionable context is preserved
        self.assertIn("host=db.example.com", error)
        self.assertIn("could not connect", error)
        self.assertIn(ATTRIBUTE_VALUE_REDACTED, error)

    def test_url_userinfo_is_stripped(self):
        message = f"connection failed: postgresql://{_USER}:{_PASSWORD}@db.example.com:5432/prod"
        response = AgentUtils._response_for_error(
            "operation failed", exception_message=message
        )
        exc = response[ATTRIBUTE_NAME_EXCEPTION]
        self.assertNotIn(_PASSWORD, exc)
        self.assertNotIn(_USER, exc)
        self.assertIn("db.example.com", exc)  # host preserved -> actionable

    def test_bearer_token_is_stripped(self):
        token = "eyJhbGciOiJIUzI1NiwidHlwIjoiSldUI.payloadsegment.signaturesegment"
        response = AgentUtils._response_for_error(
            f"401 Unauthorized: Authorization: Bearer {token}"
        )
        error = response[ATTRIBUTE_NAME_ERROR]
        self.assertNotIn(token, error)
        self.assertIn("401 Unauthorized", error)

    def test_json_blob_value_is_stripped(self):
        # a JSON-shaped secret embedded in free-form error text
        message = (
            f'request failed with body {{"user": "{_USER}", "password": "{_PASSWORD}"}}'
        )
        response = AgentUtils._response_for_error(message)
        error = response[ATTRIBUTE_NAME_ERROR]
        self.assertNotIn(_PASSWORD, error)
        self.assertNotIn(f'"{_USER}"', error)
        self.assertIn("request failed with body", error)

    def test_benign_auth_message_is_left_intact(self):
        # the word "password" with no key=value form must NOT trigger redaction
        message = "FATAL: password authentication failed for user"
        response = AgentUtils._response_for_error(message)
        self.assertEqual(response[ATTRIBUTE_NAME_ERROR], message)

    def test_missing_field_message_is_left_intact(self):
        # CTP validation errors name fields; no secret value is present
        message = "Missing required fields: ['password', 'user']"
        response = AgentUtils._response_for_error(message)
        self.assertEqual(response[ATTRIBUTE_NAME_ERROR], message)

    def test_stack_trace_strips_values_per_frame(self):
        stack_trace = [
            '  File "proxy.py", line 10, in connect\n    db.connect()\n',
            f'  File "pg.py", line 42, in _open\n    connect("host=h user={_USER} password={_PASSWORD}")\n',
        ]
        response = AgentUtils._response_for_error(
            "operation failed", stack_trace=stack_trace
        )
        result = response[ATTRIBUTE_NAME_STACK_TRACE]
        self.assertEqual(result[0], stack_trace[0])  # benign frame untouched
        self.assertNotIn(_PASSWORD, result[1])
        self.assertIn("pg.py", result[1])  # frame still readable

    def test_error_attrs_are_redacted_by_key(self):
        response = AgentUtils._response_for_error(
            "operation failed",
            error_attrs={"password": _PASSWORD, "host": "db.example.com"},
        )
        attrs = response[ATTRIBUTE_NAME_ERROR_ATTRS]
        self.assertEqual(attrs["password"], ATTRIBUTE_VALUE_REDACTED)
        self.assertEqual(attrs["host"], "db.example.com")

    def test_error_type_is_preserved(self):
        response = AgentUtils._response_for_error(
            f"password={_PASSWORD}", error_type="OperationalError"
        )
        self.assertEqual(response[ATTRIBUTE_NAME_ERROR_TYPE], "OperationalError")

    def test_public_error_response_strips_connect_string(self):
        # mirrors the Azure unhandled-exception handler shape
        agent_response = AgentUtils.agent_response_for_error(
            f"Internal Server Error: could not connect: user={_USER} password={_PASSWORD}",
            stack_trace=[f'  connect("password={_PASSWORD}")\n'],
        )
        serialized = str(agent_response.result)
        self.assertNotIn(_PASSWORD, serialized)
        self.assertIn(
            "Internal Server Error", agent_response.result[ATTRIBUTE_NAME_ERROR]
        )
