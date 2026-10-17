"""Configuration loader tests. Run: python -m unittest tests.test_config -v"""
from __future__ import annotations

import json
import os
import tempfile
import unittest

from aegis.config import Settings, load_settings


class ConfigTests(unittest.TestCase):
    def test_defaults_are_placeholders(self):
        s = Settings()
        self.assertFalse(s.is_ready())
        self.assertIn("gcp_project_id", s.placeholders())
        self.assertIn("stripe_api_key", s.placeholders())

    def test_load_from_json_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json",
                                         delete=False) as f:
            json.dump({"environment": "staging",
                       "gcp_project_id": "my-proj"}, f)
            path = f.name
        try:
            s = load_settings(path)
            self.assertEqual(s.environment, "staging")
            self.assertEqual(s.gcp_project_id, "my-proj")
        finally:
            os.unlink(path)

    def test_env_overrides_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json",
                                         delete=False) as f:
            json.dump({"gcp_project_id": "from-file"}, f)
            path = f.name
        try:
            s = load_settings(path, env={"AEGIS_GCP_PROJECT_ID": "from-env"})
            self.assertEqual(s.gcp_project_id, "from-env")
        finally:
            os.unlink(path)

    def test_kms_resource_name(self):
        s = Settings(gcp_project_id="p", gcp_region="r", kms_key_ring="kr",
                     kms_key="k", kms_key_version="1")
        self.assertEqual(
            s.kms_key_version_resource,
            "projects/p/locations/r/keyRings/kr/cryptoKeys/k/"
            "cryptoKeyVersions/1")

    def test_is_ready_when_no_placeholders(self):
        s = Settings(gcp_project_id="p", gemini_project="p",
                     feed_fsisac_api_key="k1", feed_hisac_api_key="k2",
                     feed_cisa_api_key="k3", stripe_api_key="s",
                     database_url="db")
        self.assertTrue(s.is_ready())
        self.assertEqual(s.placeholders(), {})


if __name__ == "__main__":
    unittest.main()
