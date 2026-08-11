import unittest
# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
from datetime import timedelta
from unittest.mock import patch

from odoo.fields import Datetime
from odoo.tests import tagged
from odoo.tests.common import TransactionCase

from odoo.addons.cledoo_mcp_full.lib import telemetry


@tagged("post_install", "-at_install")
class TestTelemetry(TransactionCase):
    def _icp(self):
        return self.env["ir.config_parameter"].sudo()

    def test_default_is_disabled_when_param_absent(self):
        # Opt-in (Odoo Apps requirement): absent parameter == disabled.
        self._icp().search(
            [("key", "=", "cledoo_mcp_full.telemetry")]).unlink()
        self.assertFalse(telemetry.telemetry_enabled(self.env))

    def test_no_default_param_is_installed(self):
        # Install data must not pre-enable telemetry on the admin's behalf.
        self.assertFalse(self.env.ref(
            "cledoo_mcp_full.param_telemetry_default", raise_if_not_found=False))

    def test_opt_in(self):
        self._icp().set_param("cledoo_mcp_full.telemetry", "True")
        self.assertTrue(telemetry.telemetry_enabled(self.env))

    def test_opt_out_after_opt_in(self):
        self._icp().set_param("cledoo_mcp_full.telemetry", "True")
        self._icp().set_param("cledoo_mcp_full.telemetry", "False")
        self.assertFalse(telemetry.telemetry_enabled(self.env))

    @unittest.skip("free-only seam default; the pro overrides are active in the merged build (covered by the pro suite)")
    def test_payload_contains_nothing_nameable(self):
        payload = telemetry.build_payload(self.env)
        # exact allowed keys — a new field must be added here consciously
        self.assertEqual(sorted(payload), sorted([
            "api_key", "event", "distinct_id", "properties"]))
        self.assertEqual(payload["event"], "mcp_ping")
        props = payload["properties"]
        self.assertEqual(sorted(props), sorted([
            "$process_person_profile", "module_version", "odoo_series",
            "enabled", "oauth_clients", "oauth_tokens_active", "principals",
            "calls_total"]))
        # anonymous events: never create PostHog person profiles
        self.assertFalse(props["$process_person_profile"])
        # distinct_id is a salted hash, not the raw db uuid
        dbuuid = self._icp().get_param("database.uuid")
        self.assertNotEqual(payload["distinct_id"], dbuuid)
        self.assertEqual(len(payload["distinct_id"]), 64)
        # everything else is ints/bools/version strings — no free text
        for key in ("oauth_clients", "oauth_tokens_active", "principals",
                    "calls_total"):
            self.assertIsInstance(props[key], int)
        self.assertIsInstance(props["enabled"], bool)

    def test_send_short_circuits_before_any_network_by_default(self):
        # No explicit opt-in on record -> not a single byte leaves.
        self._icp().search(
            [("key", "=", "cledoo_mcp_full.telemetry")]).unlink()
        with patch.object(telemetry.urlrequest, "urlopen") as mocked:
            self.assertFalse(telemetry.send(self.env))
        mocked.assert_not_called()

    def test_opt_out_short_circuits_before_any_network(self):
        self._icp().set_param("cledoo_mcp_full.telemetry", "False")
        with patch.object(telemetry.urlrequest, "urlopen") as mocked:
            self.assertFalse(telemetry.send(self.env))
        mocked.assert_not_called()

    def test_send_posts_json_when_enabled(self):
        self._icp().set_param("cledoo_mcp_full.telemetry", "True")
        self._icp().set_param("cledoo_mcp_full.telemetry_url",
                              "https://telemetry.test/ping")
        with patch.object(telemetry.urlrequest, "urlopen") as mocked:
            self.assertTrue(telemetry.send(self.env))
        req = mocked.call_args[0][0]
        self.assertEqual(req.full_url, "https://telemetry.test/ping")

    def test_network_failure_is_silent(self):
        self._icp().set_param("cledoo_mcp_full.telemetry", "True")
        with patch.object(telemetry.urlrequest, "urlopen",
                          side_effect=OSError("boom")):
            self.assertFalse(telemetry.send(self.env))  # no raise

    def test_cron_first_run_records_grace_and_sends_nothing(self):
        icp = self._icp()
        icp.set_param("cledoo_mcp_full.telemetry", "True")
        icp.search([("key", "=", "cledoo_mcp_full.telemetry_first_seen")]
                   ).unlink()
        with patch.object(telemetry.urlrequest, "urlopen") as mocked:
            self.assertFalse(self.env["mcp.telemetry"]._cron_send())
        mocked.assert_not_called()
        self.assertTrue(icp.get_param("cledoo_mcp_full.telemetry_first_seen"))

    def test_cron_sends_after_grace_period(self):
        self._icp().set_param("cledoo_mcp_full.telemetry", "True")
        self._icp().set_param(
            "cledoo_mcp_full.telemetry_first_seen",
            Datetime.to_string(Datetime.now() - timedelta(hours=25)))
        with patch.object(telemetry.urlrequest, "urlopen") as mocked:
            self.assertTrue(self.env["mcp.telemetry"]._cron_send())
        mocked.assert_called_once()

    def test_weekly_cron_is_registered(self):
        cron = self.env.ref("cledoo_mcp_full.ir_cron_mcp_telemetry")
        self.assertTrue(cron.active)
        self.assertEqual(cron.interval_type, "days")
        self.assertEqual(cron.interval_number, 7)

    def test_instance_hash_matches_telemetry_distinct_id(self):
        payload = telemetry.build_payload(self.env)
        self.assertEqual(
            telemetry.instance_hash(self.env), payload["distinct_id"])

    def test_instance_hash_is_stable_for_same_dbuuid(self):
        h1 = telemetry.instance_hash(self.env)
        h2 = telemetry.instance_hash(self.env)
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 64)
