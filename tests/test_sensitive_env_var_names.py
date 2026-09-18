from unittest import TestCase

from apollo.common.agent.redact import is_sensitive_env_var_name


class IsSensitiveEnvVarNameTests(TestCase):
    def test_matches_credential_bearing_names(self):
        for name in [
            "MCD_DB_PASSWORD",
            "MCD_DB_PASSPHRASE",
            "MCD_X_SECRET",
            "MCD_API_TOKEN",
            "MCD_STORAGE_ACCESS_KEY",
            "MCD_STORAGE_SECRET_KEY",
            "MCD_SVC_CREDENTIAL",
            "MCD_STORAGE_CONNECTION_STRING",  # embeds AccountKey=...
        ]:
            self.assertTrue(is_sensitive_env_var_name(name), name)

    def test_is_case_insensitive(self):
        self.assertTrue(is_sensitive_env_var_name("mcd_some_secret_lower"))
        self.assertTrue(is_sensitive_env_var_name("MCD_Storage_Connection_String"))

    def test_keeps_ordinary_settings_visible(self):
        for name in [
            "MCD_ORACLE_THICK_MODE",
            "MCD_AGENT_WRAPPER_TYPE",
            "MCD_STORAGE",
            "MCD_STORAGE_BUCKET_NAME",
            "MCD_LOG_FORMAT",
            "MCD_OPS_RUNNER_THREAD_COUNT",
            "MCD_DB_CONNECTION_TIMEOUT",  # "connection_string", not "connection"
            "MCD_CLIENT_CACHE_EXPIRATION_SECONDS",  # "client" is not a marker here
        ]:
            self.assertFalse(is_sensitive_env_var_name(name), name)
