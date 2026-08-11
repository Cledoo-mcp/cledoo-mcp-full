# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2026 Cledoo
"""Minimal JSON-RPC 2.0 helpers for the MCP transport."""
from dataclasses import dataclass
from typing import Any


@dataclass
class JsonRpcRequest:
    id: Any
    method: str
    params: dict


def parse_request(payload: dict) -> JsonRpcRequest:
    return JsonRpcRequest(
        id=payload.get("id"),
        method=payload.get("method") or "",
        params=payload.get("params") or {},
    )


def make_result(req_id: Any, result: Any) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def make_error(req_id: Any, code: int, message: str, data: Any = None) -> dict:
    err = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": req_id, "error": err}
