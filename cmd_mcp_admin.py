#!/usr/bin/env python3
"""
shell-stream-admin (Windows: self-elevating)
- Same streaming tools as 'shell-stream' (start/read/status/stop)
- On Windows: if not elevated, shows UAC consent and relaunches elevated
- On macOS/Linux: refuse unless started with sudo (see notes below)

SECURITY: This process runs with admin privileges. Only run on a machine you trust.
"""

import os
import sys
import platform
import subprocess
import threading
import tempfile
import uuid
import time
import ctypes
from typing import Optional, Dict, Any, List

from mcp.server.fastmcp import FastMCP

# ---------------------- elevation helpers ----------------------
def _is_admin() -> bool:
    """Windows: via IsUserAnAdmin; POSIX: euid==0."""
    if platform.system() == "Windows":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    else:
        return os.geteuid() == 0

def _windows_elevate_self() -> None:
    """
    Relaunch this script with UAC. If successful, this (non-elevated) process exits.
    """
    params = " ".join(f'"{a}"' for a in sys.argv)  # pass through all args
    rc = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, params, None, 1
    )
    if rc <= 32:
        raise PermissionError(f"UAC elevation failed/cancelled (code {rc})")
    # Child (elevated) will continue; terminate this one
    os._exit(0)

# ---------------------- MCP server ----------------------
mcp = FastMCP(
    "shell-stream-admin",
    instructions="Admin shell executor (streaming). Will ask for elevation (Windows)."
)

# ---------------------- shell launcher ----------------------
def _launcher(shell: Optional[str] = None) -> List[str]:
    sysname = platform.system()
    sh = (shell or "").lower()
    if sysname == "Windows":
        if sh in ("powershell", "pwsh"):
            return ["powershell", "-NoProfile", "-NonInteractive", "-Command"]
        return ["cmd.exe", "/d", "/s", "/c"]
    else:
        if sh == "bash":
            return ["bash", "-lc"]
        return ["/bin/sh", "-lc"]

# ---------------------- session management ----------------------
class Session:
    def __init__(self, command: str, shell_argv: List[str], cwd: Optional[str]):
        self.id = str(uuid.uuid4())
        self.command = command
        self.shell_argv = shell_argv
        self.cwd = cwd
        self.log_path = os.path.join(tempfile.gettempdir(), f"mcp-shell-admin-{self.id}.log")
        self.start_ts = time.time()
        self.returncode: Optional[int] = None
        self._done = threading.Event()
        self._proc: Optional[subprocess.Popen] = None

    def start(self):
        argv = self.shell_argv + [self.command]
        self._proc = subprocess.Popen(
            argv,
            cwd=self.cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True,
        )
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self):
        assert self._proc is not None
        with open(self.log_path, "a", encoding="utf-8", errors="replace") as f:
            f.write(f"$ {' '.join(self.shell_argv + [self.command])}\n")
            f.flush()
            if self._proc.stdout is not None:
                for line in self._proc.stdout:
                    f.write(line)
                    f.flush()
        self._proc.wait()
        self.returncode = self._proc.returncode
        with open(self.log_path, "a", encoding="utf-8", errors="replace") as f:
            f.write(f"\n[exit {self.returncode}]\n")
        self._done.set()

    def stop(self) -> bool:
        if not self._proc or self._proc.poll() is not None:
            return False
        try:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
            return True
        finally:
            pass

    @property
    def running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

SESSIONS: Dict[str, Session] = {}

# ---------------------- tools ----------------------
@mcp.tool()
def is_admin() -> dict:
    """Report whether this server process is elevated."""
    return {"os": platform.system(), "is_admin": _is_admin()}

@mcp.tool()
def start(command: str, shell: Optional[str] = None, cwd: Optional[str] = None) -> Dict[str, Any]:
    """
    Start a long-running admin-privileged command.
    Refuses to run if the process isn't elevated (defense-in-depth).
    """
    if not _is_admin():
        raise PermissionError("This server is not elevated. Relaunch with admin privileges.")

    sess = Session(command=command, shell_argv=_launcher(shell), cwd=cwd)
    SESSIONS[sess.id] = sess
    sess.start()
    return {
        "session_id": sess.id,
        "argv": sess.shell_argv + [command],
        "log_path": sess.log_path,
        "note": "Use read(session_id, offset) to stream output; status() for state; stop() to terminate."
    }

@mcp.tool()
def read(session_id: str, offset: int = 0, max_bytes: int = 65536) -> Dict[str, Any]:
    """Read a chunk from the session log."""
    sess = SESSIONS.get(session_id)
    if not sess:
        raise ValueError("Unknown session_id")
    if not os.path.exists(sess.log_path):
        return {"chunk": "", "next_offset": offset, "eof": False}
    size = os.path.getsize(sess.log_path)
    if offset > size:
        offset = size
    with open(sess.log_path, "r", encoding="utf-8", errors="replace") as f:
        f.seek(offset)
        chunk = f.read(max_bytes)
    next_offset = offset + len(chunk)
    eof = next_offset >= os.path.getsize(sess.log_path) and not sess.running
    return {
        "chunk": chunk,
        "next_offset": next_offset,
        "eof": eof,
        "running": sess.running,
        "returncode": sess.returncode
    }

@mcp.tool()
def status(session_id: str) -> Dict[str, Any]:
    """Get session status."""
    sess = SESSIONS.get(session_id)
    if not sess:
        raise ValueError("Unknown session_id")
    return {
        "running": sess.running,
        "returncode": sess.returncode,
        "started_at": sess.start_ts,
        "log_path": sess.log_path,
        "argv": sess.shell_argv + [sess.command],
    }

@mcp.tool()
def stop(session_id: str) -> Dict[str, Any]:
    """Terminate the session's process."""
    sess = SESSIONS.get(session_id)
    if not sess:
        raise ValueError("Unknown session_id")
    ok = sess.stop()
    return {"terminated": ok, "running": sess.running, "returncode": sess.returncode}

# ---------------------- entrypoint ----------------------
if __name__ == "__main__":
    sysname = platform.system()

    # If we're on Windows and not elevated, trigger UAC to relaunch elevated.
    if sysname == "Windows" and not _is_admin():
        try:
            _windows_elevate_self()  # shows UAC; exits current proc if successful
        except PermissionError as e:
            print(f"[admin] Elevation cancelled/failed: {e}", file=sys.stderr)
            sys.exit(1)

    # On POSIX, require sudo (no GUI prompt here)
    if sysname != "Windows" and not _is_admin():
        print("[admin] Please start this server with sudo (no GUI UAC on this OS).", file=sys.stderr)
        sys.exit(1)

    # Now we are elevated → serve.
    mcp.run()
