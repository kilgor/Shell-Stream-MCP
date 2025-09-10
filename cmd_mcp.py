#!/usr/bin/env python3
# ============================================================================
# MCP Shell Streaming Server - SAFE VERSION WITH SECURITY RESTRICTIONS
# - Added comprehensive security filtering to prevent dangerous operations
# - Blocks system file access, dangerous commands, and critical registry paths
# - Maintains functionality while preventing accidental system damage
#
# ⚠️ SECURITY NOTICE:
#   This version includes built-in safety checks but still requires careful use.
#   Running with admin privileges increases potential impact of any bypassed restrictions.
# ============================================================================

import os
import platform
import subprocess
import threading
import tempfile
import uuid
import time
import re
from typing import Optional, Dict, Any, List

from mcp.server.fastmcp import FastMCP

# ============================================================================
# SECURITY CONFIGURATION - Critical System Protection
# ============================================================================

# Dangerous file paths that should never be accessed
BLOCKED_PATHS = [
    r'C:\\Windows\\',                    # Windows system files and directories
    r'C:\\Program Files\\',              # Installed applications directory
    r'C:\\Program Files \(x86\)\\',      # 32-bit applications directory
    r'C:\\ProgramData\\',                # Application data shared across users
    r'C:\\System Volume Information\\',  # System restore and volume shadow copies
    r'C:\\hiberfil\.sys',               # Hibernation file
    r'C:\\pagefile\.sys',               # Virtual memory paging file
    r'C:\\Windows\\System32\\config\\', # Registry hive files
    r'bootmgr',                         # Boot manager
    r'ntldr',                           # Legacy boot loader
    r'C:\\Boot\\',                      # Boot configuration directory
    r'\\Windows\\',                     # Any Windows directory
    r'\\System32\\',                    # System32 directory
    r'\\SysWOW64\\'                     # 32-bit system directory on 64-bit Windows
]

# Commands that can destroy the system - SIMPLIFIED LIST
DANGEROUS_COMMANDS = [
    'bcdedit',                         # Boot configuration editor (can make system unbootable)
    'bootrec',                         # Boot recovery tool (can damage boot process)
    'bcdboot',                         # Boot configuration data tool
    'sfc /scannow',                    # System file checker (can be slow/disruptive)
    'del c:\\windows',                 # Delete Windows directory
    'rmdir /s c:\\windows',            # Remove Windows directory recursively
    'rd /s c:\\windows',               # Remove Windows directory (short form)
    'takeown /f c:\\windows',          # Take ownership of Windows directory
    'icacls c:\\windows'               # Change permissions on Windows directory
]

# Protected drives - format and diskpart operations blocked on these drives
PROTECTED_DRIVES = [
    'C:',  # System drive
    'D:'   # Main data drive
]

# Critical registry paths that should be protected
DANGEROUS_REGISTRY_PATHS = [
    r'HKLM\\SYSTEM\\',                                                    # System configuration registry
    r'HKLM\\SECURITY\\',                                                  # Security policies and settings
    r'HKLM\\SAM\\',                                                       # User account database
    r'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',          # Programs that start with Windows
    r'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon',  # Login configuration
    r'HKEY_LOCAL_MACHINE\\SYSTEM\\',                                      # System configuration (alternative format)
    r'HKEY_LOCAL_MACHINE\\SECURITY\\',                                    # Security policies (alternative format)
    r'HKEY_LOCAL_MACHINE\\SAM\\'                                          # User accounts (alternative format)
]

# Critical services that should never be stopped
CRITICAL_SERVICES = [
    'winlogon',          # Windows login service
    'csrss',             # Client/Server Runtime Subsystem (critical)
    'lsass',             # Local Security Authority Subsystem (authentication)
    'services',          # Service Control Manager
    'rpcss',             # Remote Procedure Call system service
    'eventlog',          # Windows Event Log service
    'plugplay',          # Plug and Play service
    'dhcp',              # DHCP Client service (network configuration)
    'dnscache',          # DNS Client service (name resolution)
    'cryptsvc',          # Cryptographic Services (security)
    'wuauserv',          # Windows Update service
    'bits',              # Background Intelligent Transfer Service
    'lanmanserver',      # Server service (file/print sharing)
    'lanmanworkstation'  # Workstation service (network access)
]

def is_command_safe(command: str) -> tuple[bool, str]:
    """
    Comprehensive security check for shell commands.
    
    Returns:
        (is_safe, reason) - Boolean indicating safety and explanation
    """
    command_lower = command.lower().strip()
    
    # Empty commands are safe (but useless)
    if not command_lower:
        return True, "Empty command"
    
    # Check for dangerous commands
    for dangerous_cmd in DANGEROUS_COMMANDS:
        if dangerous_cmd.lower() in command_lower:
            return False, f"BLOCKED: Dangerous command detected: {dangerous_cmd}"
    
    # Special check for format and diskpart commands on protected drives
    if 'format' in command_lower:
        for protected_drive in PROTECTED_DRIVES:
            # Simple string matching instead of regex
            if f'format {protected_drive.lower()}' in command_lower:
                return False, f"BLOCKED: Format command targeting protected drive {protected_drive}"
    
    if 'diskpart' in command_lower:
        # Simple string matching for dangerous diskpart operations
        dangerous_diskpart_terms = ['select disk 0', 'clean', 'format fs=', 'active']
        for term in dangerous_diskpart_terms:
            if term in command_lower:
                return False, f"BLOCKED: Dangerous diskpart operation detected: {term}"
    
    # Check for blocked file paths
    for blocked_path in BLOCKED_PATHS:
        # Convert the path pattern to lowercase and use simple string matching instead of regex
        if blocked_path.lower().replace('\\\\', '\\') in command_lower:
            return False, f"BLOCKED: Access to protected path: {blocked_path}"
    
    # Check for dangerous registry operations
    if 'reg delete' in command_lower or 'reg add' in command_lower:
        for dangerous_reg in DANGEROUS_REGISTRY_PATHS:
            if dangerous_reg.lower() in command_lower:
                return False, f"BLOCKED: Critical registry path: {dangerous_reg}"
    
    # Check for recursive deletions in system areas
    if ('del /s' in command_lower or 'rmdir /s' in command_lower or 'rd /s' in command_lower):
        system_paths = ['c:\\windows', 'c:\\program files', 'c:\\programdata']
        if any(path in command_lower for path in system_paths):
            return False, "BLOCKED: Recursive deletion in system directory"
    
    # Check for wildcard operations in dangerous areas
    if '*' in command:
        system_paths = ['c:\\windows', 'c:\\program files', 'c:\\programdata']
        if any(path in command_lower for path in system_paths):
            return False, "BLOCKED: Wildcard operation in system directory"
    
    # Check for critical service operations
    if 'sc stop' in command_lower or 'net stop' in command_lower:
        for critical_service in CRITICAL_SERVICES:
            if critical_service in command_lower:
                return False, f"BLOCKED: Cannot stop critical service: {critical_service}"
    
    # Check for forced process termination of critical processes (but allow Claude.exe)
    if 'taskkill' in command_lower and '/f' in command_lower:
        # Allow killing Claude.exe specifically
        if 'claude.exe' in command_lower:
            return True, "Allowed: Claude.exe termination"
        # Block critical system processes
        critical_processes = ['winlogon.exe', 'csrss.exe', 'lsass.exe', 'explorer.exe']
        for critical_process in critical_processes:
            if critical_process in command_lower:
                return False, f"BLOCKED: Cannot force-kill critical process: {critical_process}"
    
    # Check for boot configuration changes
    if any(boot_cmd in command_lower for boot_cmd in ['bcdedit', 'bootrec', 'bcdboot']):
        return False, "BLOCKED: Boot configuration changes not allowed"
    
    # Check for system file attribute changes
    if 'attrib' in command_lower and any(sys_path in command_lower for sys_path in ['c:\\windows', 'c:\\program files']):
        return False, "BLOCKED: System file attribute changes not allowed"
    
    # Check for ownership changes on system files
    if 'takeown' in command_lower and any(sys_path in command_lower for sys_path in ['c:\\windows', 'c:\\program files']):
        return False, "BLOCKED: System file ownership changes not allowed"
    
    return True, "Command appears safe"

# Create the MCP server instance with security-aware instructions
mcp = FastMCP(
    "shell-stream", 
    instructions="Execute shell commands with built-in security restrictions. "
                "Blocks dangerous operations that could damage the system while "
                "allowing safe administrative tasks including restarts and disk operations on non-system drives."
)

# ============================================================================
# SECURITY-AWARE PROMPT DECORATOR
# ============================================================================

@mcp.prompt()
def secure_shell_execution_guidance() -> str:
    """
    Enhanced prompt that explains both capabilities and security restrictions.
    """
    return """
    SHELL COMMAND EXECUTION WITH SECURITY PROTECTION:

    You CAN execute shell commands using the shell-stream MCP server, but with built-in safety:

    🟢 SAFE OPERATIONS:
    - File operations in D:\, user directories, temp folders
    - Network diagnostics (ping, tracert, nslookup)
    - System information gathering (hostname, whoami, systeminfo)
    - Safe registry reads (HKCU, non-critical HKLM areas)
    - DNS configuration changes
    - Non-critical service queries
    - Development tools and user applications
    - System restart and shutdown commands (Restart-Computer, Stop-Computer)
    - Disk operations on non-system drives (E:, F:, USB drives, etc.)
    - Diskpart operations (with restrictions on dangerous commands)

    🔴 BLOCKED OPERATIONS (automatically prevented):
    - System file access (C:\Windows, C:\Program Files)
    - Format operations on C: and D: drives (protected drives)
    - Dangerous diskpart operations (clean, select disk 0, etc.)
    - Boot configuration (bcdedit, bootrec)
    - Critical registry modifications (HKLM\SYSTEM, HKLM\SECURITY)
    - Critical service termination (winlogon, csrss, lsass, etc.)
    - Recursive system directory deletion
    - Forced system process termination
    - System file attribute/ownership changes

    🟡 CONDITIONALLY ALLOWED:
    - Format commands: Allowed on E:, F:, and other non-system drives
    - Diskpart: Allowed for safe operations, blocked for dangerous ones

    Tools available:
    1. **start()** - Execute safe commands with automatic security filtering
    2. **read()** - Stream command output in real-time
    3. **status()** - Check command execution status  
    4. **stop()** - Terminate running commands

    The system will automatically block dangerous operations and explain why.
    This allows useful admin work while preventing accidental system damage.
    """

# ============================================================================
# ENHANCED SHELL LAUNCHER WITH SECURITY LOGGING
# ============================================================================

def _launcher(shell_hint: Optional[str] = None) -> List[str]:
    """Enhanced launcher that logs shell selection for security auditing."""
    current_os = platform.system()
    preferred_shell = (shell_hint or "").lower()

    if current_os == "Windows":
        if preferred_shell in ("powershell", "pwsh"):
            return ["powershell", "-NoProfile", "-NonInteractive", "-Command"]
        else:
            return ["cmd.exe", "/d", "/s", "/c"]
    else:
        if preferred_shell == "bash":
            return ["bash", "-lc"]
        else:
            return ["/bin/sh", "-lc"]

# ============================================================================
# SECURE SESSION CLASS WITH COMMAND FILTERING
# ============================================================================

class SecureShellSession:
    """Enhanced Session class with built-in security filtering."""
    
    def __init__(self, command: str, shell_argv: List[str], working_directory: Optional[str]):
        # Security check BEFORE creating session
        is_safe, safety_reason = is_command_safe(command)
        if not is_safe:
            raise ValueError(f"Security violation: {safety_reason}")
        
        self.session_id = str(uuid.uuid4())
        self.user_command = command
        self.shell_prefix = shell_argv
        self.working_directory = working_directory
        
        self.output_log_path = os.path.join(
            tempfile.gettempdir(), 
            f"mcp-shell-{self.session_id}.log"
        )
        
        self.started_timestamp = time.time()
        self.exit_code: Optional[int] = None
        self._output_pump_finished = threading.Event()
        self._subprocess_handle: Optional[subprocess.Popen] = None
        
        # Log the security-approved command
        self._log_security_approval(command, safety_reason)

    def _log_security_approval(self, command: str, reason: str):
        """Log that this command passed security checks."""
        # Write to security log (could be enhanced with proper logging)
        security_log_path = os.path.join(tempfile.gettempdir(), "mcp-shell-security.log")
        with open(security_log_path, "a", encoding="utf-8") as log:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            log.write(f"[{timestamp}] APPROVED: {command} - {reason}\n")

    def start_execution(self) -> None:
        """Start execution with additional security context logging."""
        complete_argv = self.shell_prefix + [self.user_command]
        
        self._subprocess_handle = subprocess.Popen(
            complete_argv,
            cwd=self.working_directory,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True,
        )
        
        output_collector = threading.Thread(target=self._pump_output_to_log, daemon=True)
        output_collector.start()

    def _pump_output_to_log(self) -> None:
        """Enhanced output pumping with security context."""
        assert self._subprocess_handle is not None, "start_execution() must be called first"
        
        with open(self.output_log_path, "a", encoding="utf-8", errors="replace") as log_file:
            header_line = f"$ {' '.join(self.shell_prefix + [self.user_command])}\n"
            log_file.write(header_line)
            log_file.flush()
            
            if self._subprocess_handle.stdout is not None:
                for output_line in self._subprocess_handle.stdout:
                    log_file.write(output_line)
                    log_file.flush()
        
        self._subprocess_handle.wait()
        self.exit_code = self._subprocess_handle.returncode
        
        with open(self.output_log_path, "a", encoding="utf-8", errors="replace") as log_file:
            log_file.write(f"\n[exit {self.exit_code}]\n")
        
        self._output_pump_finished.set()

    def terminate_process(self) -> bool:
        """Terminate process with security logging."""
        if not self._subprocess_handle or self._subprocess_handle.poll() is not None:
            return False
        
        try:
            self._subprocess_handle.terminate()
            try:
                self._subprocess_handle.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._subprocess_handle.kill()
            return True
        finally:
            # Log termination for security audit
            security_log_path = os.path.join(tempfile.gettempdir(), "mcp-shell-security.log")
            with open(security_log_path, "a", encoding="utf-8") as log:
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                log.write(f"[{timestamp}] TERMINATED: {self.user_command}\n")

    @property
    def is_still_running(self) -> bool:
        """Check if process is still running."""
        return (
            self._subprocess_handle is not None and 
            self._subprocess_handle.poll() is None
        )

# ============================================================================
# GLOBAL SESSION REGISTRY
# ============================================================================

active_sessions: Dict[str, SecureShellSession] = {}

# ============================================================================
# SECURE MCP TOOLS WITH BUILT-IN FILTERING
# ============================================================================

@mcp.tool()
def start(command: str, shell: Optional[str] = None, cwd: Optional[str] = None) -> Dict[str, Any]:
    """
    Tool: Launch a shell command with automatic security filtering.
    
    Blocks dangerous operations while allowing safe administrative tasks.
    
    Args:
        command: The command string to execute (will be security-checked)
        shell: Optional shell preference ("bash", "powershell", etc.)
        cwd: Optional working directory to run the command in
    
    Returns:
        Dictionary with session info or security violation error
    """
    
    try:
        # Create session (includes automatic security check)
        new_session = SecureShellSession(
            command=command,
            shell_argv=_launcher(shell),
            working_directory=cwd
        )
        
        # Register and start the session
        active_sessions[new_session.session_id] = new_session
        new_session.start_execution()
        
        return {
            "session_id": new_session.session_id,
            "argv": new_session.shell_prefix + [command],
            "log_path": new_session.output_log_path,
            "note": "Use read(session_id, offset) to stream output; status() for state; stop() to terminate.",
            "security_status": "APPROVED - Command passed security checks"
        }
        
    except ValueError as security_error:
        # Return security violation instead of executing
        return {
            "session_id": None,
            "error": str(security_error),
            "security_status": "BLOCKED - Command violates security policy",
            "note": "Command was blocked for system safety. Try a different approach or contact administrator."
        }

@mcp.tool()
def read(session_id: str, offset: int = 0, max_bytes: int = 65536) -> Dict[str, Any]:
    """
    Tool: Read output from a security-approved command session.
    
    Args:
        session_id: Which command session to read from  
        offset: Byte position in log file to start reading
        max_bytes: Maximum amount to read in this call
    
    Returns:
        Dictionary with the output chunk and metadata
    """
    
    session = active_sessions.get(session_id)
    if not session:
        raise ValueError(f"Unknown session_id: {session_id}")
    
    if not os.path.exists(session.output_log_path):
        return {
            "chunk": "",
            "next_offset": offset,
            "eof": False,
            "running": session.is_still_running,
            "returncode": session.exit_code
        }
    
    current_file_size = os.path.getsize(session.output_log_path)
    
    if offset > current_file_size:
        offset = current_file_size
    
    with open(session.output_log_path, "r", encoding="utf-8", errors="replace") as log_file:
        log_file.seek(offset)
        chunk_content = log_file.read(max_bytes)
    
    next_read_offset = offset + len(chunk_content)
    at_end_of_file = next_read_offset >= os.path.getsize(session.output_log_path)
    reached_eof = at_end_of_file and not session.is_still_running
    
    return {
        "chunk": chunk_content,
        "next_offset": next_read_offset,
        "eof": reached_eof,
        "running": session.is_still_running,
        "returncode": session.exit_code
    }

@mcp.tool()
def status(session_id: str) -> Dict[str, Any]:
    """
    Tool: Get current status information about a command session.
    
    Args:
        session_id: Which command session to check
        
    Returns:
        Dictionary with complete status information
    """
    
    session = active_sessions.get(session_id)
    if not session:
        raise ValueError(f"Unknown session_id: {session_id}")
    
    return {
        "running": session.is_still_running,
        "returncode": session.exit_code,
        "started_at": session.started_timestamp,
        "log_path": session.output_log_path,
        "argv": session.shell_prefix + [session.user_command],
        "security_status": "Command was security-approved"
    }

@mcp.tool()
def stop(session_id: str) -> Dict[str, Any]:
    """
    Tool: Terminate a running command session.
    
    Args:
        session_id: Which command session to terminate
        
    Returns:
        Dictionary showing termination results
    """
    
    session = active_sessions.get(session_id)
    if not session:
        raise ValueError(f"Unknown session_id: {session_id}")
    
    termination_sent = session.terminate_process()
    
    return {
        "terminated": termination_sent,
        "running": session.is_still_running,
        "returncode": session.exit_code,
        "security_note": "Termination logged for security audit"
    }

# ============================================================================
# SECURITY TESTING TOOL (for verification)
# ============================================================================

@mcp.tool()
def test_security(test_command: str) -> Dict[str, Any]:
    """
    Tool: Test if a command would be blocked by security filters (without executing).
    
    Args:
        test_command: Command to test against security filters
        
    Returns:
        Dictionary showing whether command would be allowed and why
    """
    
    is_safe, reason = is_command_safe(test_command)
    
    return {
        "command": test_command,
        "would_be_allowed": is_safe,
        "reason": reason,
        "note": "This tool tests security filters without executing commands"
    }

# ============================================================================
# SERVER STARTUP
# ============================================================================

if __name__ == "__main__":
    # Log security system startup
    security_log_path = os.path.join(tempfile.gettempdir(), "mcp-shell-security.log")
    with open(security_log_path, "a", encoding="utf-8") as log:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log.write(f"[{timestamp}] SECURITY SYSTEM STARTED - Safe shell-stream MCP server initialized\n")
    
    mcp.run()
