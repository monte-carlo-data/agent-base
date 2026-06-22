from logging import INFO, Formatter, LogRecord
from unittest import TestCase

from apollo.common.agent.constants import ATTRIBUTE_VALUE_REDACTED
from apollo.common.agent.redact_formatter import RedactFormatterWrapper


class RedactFormatterWrapperTests(TestCase):
    """Tests for RedactFormatterWrapper (redacts formatted log output)."""

    @staticmethod
    def _record(msg, args):
        return LogRecord(
            name="test",
            level=INFO,
            pathname="path",
            lineno=1,
            msg=msg,
            args=args,
            exc_info=None,
        )

    @staticmethod
    def _wrapper():
        return RedactFormatterWrapper(Formatter("%(message)s"))

    def test_redactable_message_with_args_does_not_raise(self):
        """Regression: when a record's message redacts to the redacted marker and
        the record also carries %-args, formatting must not raise "not all
        arguments converted during string formatting".

        The wrapper must redact the FULLY FORMATTED message, not the format
        string: redacting the format string first collapses it to the marker
        (dropping the %-placeholders), so the subsequent %-substitution then
        fails. This broke azure-identity's credential logging on the Azure
        Functions worker (the error propagated via the OpenTelemetry log handler
        and was recorded as a credential failure)."""
        record = self._record('{"password": "secret123"} %s', ("downstream",))
        self.assertEqual(self._wrapper().format(record), ATTRIBUTE_VALUE_REDACTED)

    def test_secret_passed_as_arg_is_redacted(self):
        """A secret supplied as a %-arg is redacted, since the fully substituted
        line is what gets redacted."""
        record = self._record('{"password": "%s"}', ("secret123",))
        self.assertEqual(self._wrapper().format(record), ATTRIBUTE_VALUE_REDACTED)

    def test_non_sensitive_message_with_args_is_formatted(self):
        """A normal message with %-args is formatted normally."""
        record = self._record("processed %s rows", (42,))
        self.assertEqual(self._wrapper().format(record), "processed 42 rows")
