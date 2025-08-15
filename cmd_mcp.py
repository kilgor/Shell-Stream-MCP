#!/usr/bin/env python3
# ============================================================================
# MCP Shell Streaming Server
# - Exposes long-running shell execution as MCP tools.
# - You can start a shell command, tail its output in chunks, query its status,
#   and stop it if needed.
#
# ⚠️ SECURITY WARNING:
#   This server can execute arbitrary shell commands on the host machine.
#   Use only in a controlled/isolated environment, preferably with a low-
#   privilege account. Any command the host can run, this process can run.
# ============================================================================

import os
import platform
import subprocess
import threading
import tempfile
import uuid
import time
from typing import Optional, Dict, Any, List

from mcp.server.fastmcp import FastMCP

# Create the MCP server instance.
# - The first argument is the server name that clients will see.
# - 'instructions' is a human-readable description for hosts/LLMs.
mcp = FastMCP("shell-stream", instructions="Run long-lived shell commands and tail output.")

# ---------------------- shell launcher ----------------------
def _launcher(shell: Optional[str] = None) -> List[str]:
    """
    Decide which shell to use based on the OS and an optional user 'shell' hint.
    Returns an argv prefix used to invoke that shell in "execute command" mode.

    On Windows:
      - Default: CMD via ["cmd.exe", "/d", "/s", "/c"]
        * /d: Disable AutoRun
        * /s: Modify handling of quotes (CMD quirk)
        * /c: Execute the command string and then terminate
      - If 'shell' is "powershell" or "pwsh": use PowerShell with flags that
        avoid profiles and interactivity.

    On POSIX (macOS/Linux):
      - Default: POSIX sh via ["/bin/sh", "-lc"]
        * -l: Login shell semantics (helps pick up PATH)
        * -c: Execute the command string
      - If 'shell' is "bash": use ["bash", "-lc"]

    The function returns only the shell prefix. The caller appends the actual
    command string as the final element when starting the process.
    """
    sys = platform.system()          # Determine the OS at runtime
    sh = (shell or "").lower()       # Normalize the optional shell hint to lowercase

    if sys == "Windows":             # Branch: Windows-specific behavior
        if sh in ("powershell", "pwsh"):  # If caller explicitly wants PowerShell
            # Use PowerShell in non-interactive mode, no profiles, run a command
            return ["powershell", "-NoProfile", "-NonInteractive", "-Command"]
        # Otherwise default to classic CMD
        return ["cmd.exe", "/d", "/s", "/c"]
    else:                            # Branch: POSIX (macOS/Linux)
        if sh == "bash":             # If caller explicitly wants bash
            return ["bash", "-lc"]
        # Otherwise default to sh
        return ["/bin/sh", "-lc"]

# ---------------------- session mgmt ------------------------
class Session:
    """
    Represents a single long-running shell command session.

    Responsibilities:
      - Start the subprocess using the chosen shell launcher
      - Continuously read combined stdout+stderr
      - Write all output to a per-session log file on disk (so memory won't blow up)
      - Track return code and whether the process is still running
    """
    def __init__(self, command: str, shell_argv: List[str], cwd: Optional[str]):
        # A unique identifier so clients can reference the session later (for read/status/stop)
        self.id = str(uuid.uuid4())

        # The raw command string to pass to the shell
        self.command = command

        # The launcher prefix that wraps the command, e.g. ["cmd.exe","/c"] or ["/bin/sh","-lc"]
        self.shell_argv = shell_argv

        # Optional working directory; None means inherit the server's current directory
        self.cwd = cwd

        # Path to the on-disk log file where we append output as it arrives.
        # tempfile.gettempdir() gives a writable temp dir across platforms.
        self.log_path = os.path.join(tempfile.gettempdir(), f"mcp-shell-{self.id}.log")

        # Timestamp when the session was started (UNIX seconds)
        self.start_ts = time.time()

        # Will hold the process's final return code (None while still running)
        self.returncode: Optional[int] = None

        # An internal event flag the pump thread sets when the process finishes
        self._done = threading.Event()

        # Handle to the running subprocess (set in start(); None until then)
        self._proc: Optional[subprocess.Popen] = None

    def start(self):
        """
        Spawn the subprocess and start a background thread to pump stdout→log.
        """
        # Build the full argv to run: shell prefix + [command string]
        argv = self.shell_argv + [self.command]

        # Launch the process:
        # - stdout is piped so we can read it
        # - stderr is merged into stdout so output is in one stream (ordering preserved)
        # - text=True gives us strings (decoding), not bytes
        # - bufsize=1 requests line-buffered I/O in text mode (best-effort)
        self._proc = subprocess.Popen(
            argv,
            cwd=self.cwd,                         # Use provided working directory (or inherit)
            stdout=subprocess.PIPE,              # Capture stdout
            stderr=subprocess.STDOUT,            # Merge stderr into stdout
            text=True,                           # Decode to str instead of bytes
            bufsize=1,                           # Line-buffered (platform-dependent)
            universal_newlines=True,             # Alias for text=True on older Python
        )

        # Create and start a daemon thread that continuously reads from the process
        # and appends to the session log file until the process exits.
        t = threading.Thread(target=self._pump, daemon=True)
        t.start()

    def _pump(self):
        """
        Background thread target:
        - Open the session log file
        - Write a one-line header with the command
        - For each line arriving from the process's stdout, append it and flush
        - When the process ends, write the [exit {code}] footer and mark done
        """
        assert self._proc is not None, "start() must be called before _pump()"

        # Open log file in append-text mode; errors='replace' avoids crashes on bad encodings
        with open(self.log_path, "a", encoding="utf-8", errors="replace") as f:
            # Write a header so the log always begins with the command that ran
            f.write(f"$ {' '.join(self.shell_argv + [self.command])}\n")
            f.flush()  # Force header to disk immediately (useful if the process is long-lived)

            # Only proceed if stdout was successfully piped
            if self._proc.stdout is not None:
                # Iterate line-by-line; this yields as the process produces output
                for line in self._proc.stdout:
                    f.write(line)   # Append the new line to the log file
                    f.flush()       # Flush so a tailing client sees updates quickly

        # Wait for the process to actually terminate (ensures returncode is set)
        self._proc.wait()

        # Record the return code for status queries
        self.returncode = self._proc.returncode

        # Append a footer to mark completion and the exit status
        with open(self.log_path, "a", encoding="utf-8", errors="replace") as f:
            f.write(f"\n[exit {self.returncode}]\n")

        # Signal that the pump work is fully done
        self._done.set()

    def stop(self) -> bool:
        """
        Try to terminate the running process.
        Returns True if a termination signal was sent; False if the process
        was already finished or never started.
        """
        # If we never started a process (None) OR it's not running anymore (poll()!=None),
        # there's nothing to stop.
        if not self._proc or self._proc.poll() is not None:
            return False

        try:
            # Ask the process to terminate gracefully (SIGTERM / CTRL-BREAK-like behavior)
            self._proc.terminate()
            try:
                # Give it up to 5 seconds to exit cleanly
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                # If it didn't exit in time, force kill it
                self._proc.kill()
            return True
        finally:
            # Nothing to do in finally here; placeholder for future cleanup hooks
            pass

    @property
    def running(self) -> bool:
        """
        True if the process is still alive; False otherwise.
        - If _proc is None, nothing is running.
        - If poll() returns None, the process hasn't finished yet.
        """
        return self._proc is not None and self._proc.poll() is None

# Global registry of sessions by ID so tools can retrieve/update them.
SESSIONS: Dict[str, Session] = {}

# ---------------------- tools -------------------------------
@mcp.tool()
def start(command: str, shell: Optional[str] = None, cwd: Optional[str] = None) -> Dict[str, Any]:
    """
    Tool: Start a long-running shell command.
    - command: the exact command string (e.g., "tracert -d 8.8.8.8")
    - shell: optional shell hint ("cmd", "powershell" on Windows; "bash" on POSIX)
    - cwd: optional working directory for the process

    Returns:
      - session_id: opaque ID used to read/status/stop later
      - argv: the full argv we used (shell prefix + command)
      - log_path: path to the per-session log file on disk
      - note: guidance for the client on how to continue (read/status/stop)
    """
    # Build the session: choose shell launcher now so it's fixed for the lifetime
    sess = Session(command=command, shell_argv=_launcher(shell), cwd=cwd)

    # Register in the global session map so other tools can find it
    SESSIONS[sess.id] = sess

    # Actually start the subprocess and the background pump thread
    sess.start()

    # Return the information the client needs to continue interacting
    return {
        "session_id": sess.id,
        "argv": sess.shell_argv + [command],
        "log_path": sess.log_path,
        "note": "Use read(session_id, offset) to stream output; status() for state; stop() to terminate."
    }

@mcp.tool()
def read(session_id: str, offset: int = 0, max_bytes: int = 65536) -> Dict[str, Any]:
    """
    Tool: Read a chunk of output from the session's log file.
    - session_id: which session to read from
    - offset: byte position in the log file to start reading (supports resume/tail)
    - max_bytes: maximum number of bytes to read in this call

    Returns:
      - chunk: the text read (may be empty)
      - next_offset: the offset you should pass on the next call
      - eof: True if we've reached the end AND the process has finished
      - running: whether the process is still running now
      - returncode: the process exit code (None if still running)
    """
    # Look up the session; if it's unknown, tell the client (likely a bad ID)
    sess = SESSIONS.get(session_id)
    if not sess:
        # Branch: missing session → this is an error for the caller
        raise ValueError("Unknown session_id")

    # If the log file hasn't been created yet (edge case), return an empty chunk
    # and say "not EOF" so the client can try again shortly.
    if not os.path.exists(sess.log_path):
        return {"chunk": "", "next_offset": offset, "eof": False}

    # Get current log size to guard against seeking past EOF
    size = os.path.getsize(sess.log_path)

    # If the requested offset is beyond current size (race condition or client bug),
    # clamp it back to size (equivalent to reading from EOF).
    if offset > size:
        offset = size

    # Open the log for reading. 'errors="replace"' ensures invalid bytes won't crash decoding.
    with open(sess.log_path, "r", encoding="utf-8", errors="replace") as f:
        # Move the file pointer to the requested offset
        f.seek(offset)
        # Read up to max_bytes from that point
        chunk = f.read(max_bytes)

    # Compute where the next read should start
    next_offset = offset + len(chunk)

    # Determine EOF:
    # - If we've read up to (or past) the file's current end
    # - AND the process is no longer running,
    #   then there will be no more data appended → EOF True.
    eof = next_offset >= os.path.getsize(sess.log_path) and not sess.running

    # Return the chunk and state flags so the client can keep polling.
    return {
        "chunk": chunk,
        "next_offset": next_offset,
        "eof": eof,
        "running": sess.running,
        "returncode": sess.returncode
    }

@mcp.tool()
def status(session_id: str) -> Dict[str, Any]:
    """
    Tool: Report the current status of a session.
    Returns:
      - running: whether the process is still alive
      - returncode: exit code (None if still running)
      - started_at: UNIX timestamp when the process began
      - log_path: where output is being written
      - argv: the exact argv used to launch the command
    """
    # Retrieve the session
    sess = SESSIONS.get(session_id)
    if not sess:
        # Branch: missing session → this is an error
        raise ValueError("Unknown session_id")

    # Build and return a state snapshot
    return {
        "running": sess.running,
        "returncode": sess.returncode,
        "started_at": sess.start_ts,
        "log_path": sess.log_path,
        "argv": sess.shell_argv + [sess.command],
    }

@mcp.tool()
def stop(session_id: str) -> Dict[str, Any]:
    """
    Tool: Attempt to terminate the running process in a session.
    Returns:
      - terminated: True if we sent a termination signal
      - running: whether the process is still alive after our attempt
      - returncode: exit code if it already finished by the time we checked
    """
    # Retrieve the session
    sess = SESSIONS.get(session_id)
    if not sess:
        # Branch: missing session → error for the caller
        raise ValueError("Unknown session_id")

    # Try to stop the process (terminate→kill fallback inside)
    ok = sess.stop()

    # Report what happened and the current state
    return {"terminated": ok, "running": sess.running, "returncode": sess.returncode}

# Standard Python entry point: when this file is executed directly,
# connect the MCP server to its transport (stdio by default) and start serving.
if __name__ == "__main__":
    mcp.run()
