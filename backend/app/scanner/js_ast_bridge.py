"""Bridge to Node @babel/parser sidecar (O-01).

NFR-01: keeps a persistent Node process (length-prefixed JSON protocol)
so per-scan cost is parse-only (~5-20ms), not process spawn (~300ms).
Falls back to one-shot spawn, then regex, if the worker is unavailable.
"""
from __future__ import annotations
import json
import struct
import subprocess
import threading
from pathlib import Path


def _resource_base() -> Path:
    """A1: resolve js-ast/ under PyInstaller _MEIPASS when frozen."""
    import os
    import sys
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        return Path(meipass)
    override = os.environ.get("CODESHIELD_RESOURCES")
    if override:
        return Path(override)
    return Path(__file__).resolve().parent.parent.parent


def _sidecar_paths() -> tuple[Path, Path]:
    base = _resource_base()
    return base / "js-ast" / "scan.js", base / "js-ast" / "worker.js"


def _node_bin() -> str:
    """A2: VS Code Electron Node first (no user Node install), then PATH node.

    The extension passes its own Node via CODESHIELD_NODE_BIN; the bundled
    exe inherits the same env, so end users never install Node.js.
    """
    import os
    for key in ("CODESHIELD_NODE_BIN", "ELECTRON_RUN_AS_NODE"):
        val = os.environ.get(key)
        if val and Path(val).exists():
            return val
    return os.environ.get("CODESHIELD_NODE", "node")

_lock = threading.Lock()
_proc: subprocess.Popen | None = None


def sidecar_available() -> bool:
    scan_js, _ = _sidecar_paths()
    return scan_js.exists()


def _start_worker() -> subprocess.Popen | None:
    global _proc
    if _proc is not None and _proc.poll() is None:
        return _proc
    _, worker_js = _sidecar_paths()
    if not worker_js.exists():
        return None
    try:
        _proc = subprocess.Popen(
            [_node_bin(), str(worker_js)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        return _proc
    except (FileNotFoundError, OSError):
        return None


def _oneshot(source: str, filename: str, scan_js: Path | None = None) -> list[dict] | None:
    if scan_js is None:
        scan_js, _ = _sidecar_paths()
    payload = json.dumps({"code": source, "filename": filename})
    try:
        proc = subprocess.run(
            [_node_bin(), str(scan_js)],
            input=payload,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None
    findings = data.get("findings")
    return findings if isinstance(findings, list) else None


def _read_exact(stream, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = stream.read(n - len(buf))
        if not chunk:
            raise EOFError("worker closed")
        buf += chunk
    return buf


def scan_with_ast(source: str, filename: str = "untitled") -> list[dict] | None:
    """Persistent-worker first, one-shot spawn fallback, None -> regex."""
    scan_js, _ = _sidecar_paths()
    if not scan_js.exists():
        return None
    with _lock:
        proc = _start_worker()
        if proc is not None and proc.stdin and proc.stdout:
            try:
                payload = json.dumps({"code": source, "filename": filename}).encode()
                proc.stdin.write(struct.pack(">I", len(payload)) + payload)
                proc.stdin.flush()
                (resp_len,) = struct.unpack(">I", _read_exact(proc.stdout, 4))
                raw = _read_exact(proc.stdout, resp_len)
                data = json.loads(raw.decode())
                findings = data.get("findings")
                if isinstance(findings, list):
                    return findings
            except Exception:
                global _proc
                try:
                    proc.kill()
                except Exception:
                    pass
                _proc = None
        return _oneshot(source, filename, scan_js)

