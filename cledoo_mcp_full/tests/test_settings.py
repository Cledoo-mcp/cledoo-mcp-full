# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
from odoo.tests import tagged
from odoo.tests.common import TransactionCase

from odoo.addons.cledoo_mcp_full.lib import telemetry


@tagged("post_install", "-at_install")
class TestMcpSettings(TransactionCase):
    def test_toggle_roundtrip_via_config_parameter(self):
        S = self.env["res.config.settings"]
        s = S.create({"mcp_enabled": True})
        s.execute()
        self.assertEqual(self.env["ir.config_parameter"].sudo().get_param(
            "cledoo_mcp_full.enabled"), "True")
        s2 = S.create({"mcp_enabled": False})
        s2.execute()
        self.assertNotEqual(self.env["ir.config_parameter"].sudo().get_param(
            "cledoo_mcp_full.enabled"), "True")

    def test_default_is_disabled(self):
        # fresh install: param absent or not "True"
        self.env["ir.config_parameter"].sudo().search(
            [("key", "=", "cledoo_mcp_full.enabled")]).unlink()
        self.assertNotEqual(self.env["ir.config_parameter"].sudo().get_param(
            "cledoo_mcp_full.enabled"), "True")

    def test_endpoint_url_computed(self):
        s = self.env["res.config.settings"].create({})
        self.assertTrue(s.mcp_endpoint_url.endswith("/mcp"))

    def test_base_url_warnings_computed(self):
        icp = self.env["ir.config_parameter"].sudo()
        icp.set_param("web.base.url", "http://erp.internal.lan")
        icp.set_param("web.base.url.freeze", "False")
        s = self.env["res.config.settings"].create({})
        self.assertTrue(s.mcp_base_url_insecure)
        self.assertTrue(s.mcp_base_url_unfrozen)
        icp.set_param("web.base.url", "https://erp.example.com")
        icp.set_param("web.base.url.freeze", "True")
        s2 = self.env["res.config.settings"].create({})
        self.assertFalse(s2.mcp_base_url_insecure)
        self.assertFalse(s2.mcp_base_url_unfrozen)

    def test_localhost_http_not_flagged(self):
        # dev instances on http://localhost must not see the warning
        self.env["ir.config_parameter"].sudo().set_param(
            "web.base.url", "http://localhost:8069")
        s = self.env["res.config.settings"].create({})
        self.assertFalse(s.mcp_base_url_insecure)

    def test_mcp_pro_url_includes_hash_when_telemetry_enabled(self):
        self.env["ir.config_parameter"].sudo().set_param(
            "cledoo_mcp_full.telemetry", "True")
        s = self.env["res.config.settings"].create({})
        expected_hash = telemetry.instance_hash(self.env)
        self.assertEqual(
            s.mcp_pro_url, "https://cledoo.com/pro?cid=%s" % expected_hash)

    def test_mcp_pro_url_omits_hash_when_telemetry_disabled(self):
        self.env["ir.config_parameter"].sudo().set_param(
            "cledoo_mcp_full.telemetry", "False")
        s = self.env["res.config.settings"].create({})
        self.assertEqual(s.mcp_pro_url, "https://cledoo.com/pro")

    def test_settings_view_uses_action_button_not_static_link(self):
        view = self.env.ref("cledoo_mcp_full.res_config_settings_view_form_mcp")
        arch = view.arch
        self.assertIn('name="action_open_mcp_pro_url"', arch)
        self.assertNotIn('href="https://cledoo.com"', arch)

    def test_action_open_guide_follows_user_lang(self):
        s = self.env["res.config.settings"].with_context(lang="en_US").create({})
        self.env.user.lang = "en_US"
        self.assertEqual(s.action_open_mcp_guide_url()["url"],
                         "https://cledoo.com/guide")
        fr = self.env["res.lang"]._activate_lang("fr_FR")
        if fr:
            self.env.user.lang = "fr_FR"
            self.assertEqual(s.action_open_mcp_guide_url()["url"],
                             "https://cledoo.com/fr/guide")

    def test_action_open_mcp_pro_url_returns_act_url(self):
        self.env["ir.config_parameter"].sudo().set_param(
            "cledoo_mcp_full.telemetry", "True")
        s = self.env["res.config.settings"].create({})
        action = s.action_open_mcp_pro_url()
        self.assertEqual(action["type"], "ir.actions.act_url")
        self.assertEqual(action["target"], "new")
        self.assertEqual(action["url"], s.mcp_pro_url)


@tagged("post_install", "-at_install")
class TestModuleVersionInSettings(TransactionCase):
    def test_settings_expose_running_module_version(self):
        # the Settings page must show which code is deployed; the manifest
        # is the truth for the running code (a stale DB version after a
        # code sync without -u would lie)
        from odoo.modules.module import get_manifest
        s = self.env["res.config.settings"].create({})
        self.assertEqual(s.mcp_module_version,
                         get_manifest("cledoo_mcp_full")["version"])
        self.assertTrue(s.mcp_module_version)

    def test_version_field_is_in_the_settings_view(self):
        arch = self.env.ref(
            "cledoo_mcp_full.res_config_settings_view_form_mcp").arch_db
        self.assertIn("mcp_module_version", arch)
