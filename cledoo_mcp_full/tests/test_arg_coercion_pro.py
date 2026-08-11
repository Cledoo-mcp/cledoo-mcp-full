# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
"""Stringified-JSON args must be rehydrated BEFORE the Pro governance
pipeline inspects them: the policy engine's fields_deny strip iterates the
explicit `fields` arg, so a '["name", "phone"]' string reaching it would
be walked character by character. Coercion lives at the transport ingress
(cledoo_mcp_full controller); this locks the end-to-end property with the
policy stack active."""
import datetime
import json

from odoo.tests import tagged
from odoo.tests.common import HttpCase

from odoo.addons.cledoo_mcp_full.tests.common import LicenseMixin


@tagged("post_install", "-at_install")
class TestArgCoercionWithPolicy(LicenseMixin, HttpCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.env["ir.config_parameter"].sudo().set_param(
            "cledoo_mcp_full.enabled", "True")
        gf = ("group_ids" if "group_ids" in cls.env["res.users"]._fields
              else "groups_id")
        cls.user = cls.env["res.users"].create({
            "name": "Coercion Pro", "login": "mcp-coercion-pro-user",
            gf: [(6, 0, [cls.env.ref("base.group_user").id,
                         cls.env.ref("base.group_partner_manager").id])]})
        expiration = datetime.datetime.now() + datetime.timedelta(days=1)
        cls.key = cls.env["res.users.apikeys"].with_user(cls.user)._generate(
            None, "coercion-pro-key", expiration)
        cls.partner = cls.env["res.partner"].create(
            {"name": "Coerced Strippy", "phone": "+33999888"})
        cls.env["mcp.policy"].sudo().create(
            {"name": "hide phones", "verdict": "allow",
             "model_pattern": "res.partner", "fields_deny": "phone"})
        cls.env.flush_all()

    def _call_tool(self, name, arguments):
        body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": name, "arguments": arguments}}
        return self.url_open("/mcp", data=json.dumps(body), headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer %s" % self.key})

    def test_stringified_fields_is_coerced_and_policy_still_strips(self):
        r = self._call_tool("search_records", {
            "model": "res.partner",
            "domain": '[["name", "=", "Coerced Strippy"]]',
            "fields": '["name", "phone"]', "limit": 5})
        self.assertEqual(r.status_code, 200)
        j = r.json()
        self.assertNotIn("error", j, j.get("error"))
        flat = str(j["result"])
        self.assertIn("Coerced Strippy", flat)
        # policy fields_deny ran on the rehydrated list, not on a string
        self.assertNotIn("+33999888", flat)
