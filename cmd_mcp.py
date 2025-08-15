#!/usr/bin/env python3
import os
import platform
import subprocess
import threading
import tempfile
import uuid
import time
from typing import Optional, Dict, Any, List

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("shell-stream", instructions="Run long-lived shell commands and tail output.")

# ---------------------- shell launcher ----------------------
def _launcher(shell: Optional[str] = None) -> List[str]:
    sys = platform.system()
    sh = (shell or "").lower()
    if sys == "Windows":
        if sh in ("powershell", "pwsh"):
            return ["powershell", "-NoProfile", "-NonInteractive", "-Command"]
        return ["cmd.exe", "/d", "/s", "/c"]  # default CMD
    else:
        if sh == "bash":
            return ["bash", "-lc"]
        return ["/bin/sh", "-lc"]  # default POSIX sh

# ---------------------- session mgmt ------------------------
class Session:
    def __init__(self, command: str, shell_argv: List[str], cwd: Optional[str]):
        self.id = str(uuid.uuid4())
        self.command = command
        self.shell_argv = shell_argv
        self.cwd = cwd
        self.log_path = os.path.join(tempfile.gettempdir(), f"mcp-shell-{self.id}.log")
        self.start_ts = time.time()
        self.returncode: Optional[int] = None
        self._done = threading.Event()
        self._proc: Optional[subprocess.Popen] = None

    def start(self):
        argv = self.shell_argv + [self.command]
        # unify stdout+stderr into one stream
        self._proc = subprocess.Popen(
            argv,
            cwd=self.cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,          # line-buffered
            universal_newlines=True,
        )
        t = threading.Thread(target=self._pump, daemon=True)
        t.start()

    def _pump(self):
        assert self._proc is not None
        with open(self.log_path, "a", encoding="utf-8", errors="replace") as f:
            # write a header
            f.write(f"$ {' '.join(self.shell_argv + [self.command])}\n")
            f.flush()
            # stream lines
            if self._proc.stdout is not None:
                for line in self._proc.stdout:
                    f.write(line)
                    # flush for near-realtime tail
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

# ---------------------- tools -------------------------------
@mcp.tool()
def start(command: str, shell: Optional[str] = None, cwd: Optional[str] = None) -> Dict[str, Any]:
    """
    Start a long-running command in the OS shell.
    Returns a session_id; use read() to fetch incremental output.
    """
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
    """
    Read a chunk from the session log starting at 'offset'.
    Returns 'chunk', 'next_offset', and 'eof'.
    """
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
    """Get current status of a session."""
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

if __name__ == "__main__":
    mcp.run()
