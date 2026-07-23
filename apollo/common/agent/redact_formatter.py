from logging import Formatter, LogRecord
from typing import Optional

from apollo.common.agent.redact import AgentRedactUtilities


class RedactFormatterWrapper(Formatter):
    def __init__(self, formatter: Optional[Formatter]):
        super().__init__()
        self._formatter = formatter or Formatter()

    def format(self, record: LogRecord) -> str:
        # Redact the FULLY FORMATTED message, not the format string. Redacting
        # record.msg before %-substitution collapses any message that matches a
        # redact pattern to the redacted marker, dropping its %-placeholders, so
        # the subsequent `record.msg % record.args` raises "not all arguments
        # converted during string formatting" whenever the record carries args.
        # Formatting first keeps redaction working and also redacts values that
        # were substituted in from record.args.
        return AgentRedactUtilities.standard_redact(self._formatter.format(record))
