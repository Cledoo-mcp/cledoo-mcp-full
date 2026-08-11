# SPDX-License-Identifier: OPL-1.0
# Copyright (c) 2026 Cledoo
"""Test helper shim. Pro no longer has a licence — features are always
on — so install_license/uninstall_license are no-ops kept only so the
existing test call sites don't all need editing."""


class LicenseMixin:
    def install_license(self, *args, **kwargs):
        return None

    def uninstall_license(self, *args, **kwargs):
        return None
