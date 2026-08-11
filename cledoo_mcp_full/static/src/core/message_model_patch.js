/* SPDX-License-Identifier: LGPL-3.0-or-later ; Copyright (c) 2026 Cledoo */
import { Message } from "@mail/core/common/message_model";
import * as recordModule from "@mail/core/common/record";
import { patch } from "@web/core/utils/patch";

// Odoo 19 declares record fields with fields.Attr; Odoo 18 with
// Record.attr. Same source tree runs on both, so feature-detect.
const attr = recordModule.fields
    ? recordModule.fields.Attr
    : recordModule.Record.attr;

patch(Message.prototype, {
    setup() {
        super.setup(...arguments);
        this.mcp_name = attr(false);
    },
});
