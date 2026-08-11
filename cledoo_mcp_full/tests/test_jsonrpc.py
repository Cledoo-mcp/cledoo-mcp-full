# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
from odoo.tests import tagged
from odoo.tests.common import TransactionCase

from odoo.addons.cledoo_mcp_full.lib.jsonrpc import make_result, make_error, parse_request


@tagged("post_install", "-at_install")
class TestJsonRpc(TransactionCase):
    def test_parse_valid(self):
        req = parse_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
        self.assertEqual(req.method, "tools/list")
        self.assertEqual(req.id, 1)
        self.assertEqual(req.params, {})

    def test_make_result_shape(self):
        self.assertEqual(
            make_result(7, {"ok": True}),
            {"jsonrpc": "2.0", "id": 7, "result": {"ok": True}},
        )

    def test_make_error_shape(self):
        err = make_error(7, -32601, "Method not found")
        self.assertEqual(err["error"]["code"], -32601)
        self.assertEqual(err["error"]["message"], "Method not found")
        self.assertEqual(err["id"], 7)
