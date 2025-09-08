# MCP Shell-Stream Server

## Overview

MCP Shell-Stream Server is a Python-based server that allows you to run, monitor, and control long-lived shell commands programmatically. It supports both Windows and Unix systems, providing real-time output streaming, session management, and remote command execution via the Model Context Protocol (MCP).

**🛡️ Security Enhanced Version:** This implementation includes comprehensive security filtering to prevent dangerous operations while maintaining administrative functionality.

## Features

- **🔧 Command Execution:** Start long-running shell commands in isolated sessions
- **📡 Real-time Streaming:** Stream command output in real time
- **📊 Session Management:** Check status and return codes of running processes
- **⛔ Process Control:** Terminate processes safely
- **🌐 Cross-platform:** Support for Windows, Linux, macOS
- **🛡️ Security Filtering:** Built-in protection against dangerous system operations
- **📝 Audit Logging:** Security event logging for command approval/blocking
- **🔍 Command Testing:** Test commands against security filters without execution

## Security Features

### 🟢 **Safe Operations (Allowed)**
- File operations in user directories, D:\ drive, temp folders
- Network diagnostics (ping, tracert, nslookup, DNS changes)
- System information gathering (hostname, whoami, systeminfo)
- Safe registry reads (HKCU, non-critical HKLM areas)
- Development tools and user applications
- System restart and shutdown commands
- Disk operations on non-system drives (E:, F:, USB drives)
- Controlled diskpart operations

### 🔴 **Blocked Operations (Automatically Prevented)**
- **System Files:** Access to C:\Windows, C:\Program Files, registry hives
- **Protected Drives:** Format operations on C: and D: drives
- **Boot Configuration:** bcdedit, bootrec, bcdboot modifications
- **Critical Processes:** Forced termination of winlogon, csrss, lsass, etc.
- **Critical Services:** Stopping essential Windows services
- **Dangerous Diskpart:** clean, select disk 0, format operations
- **System Modifications:** File attribute/ownership changes on system files

### 🟡 **Conditionally Allowed**
- **Format Commands:** Allowed on E:, F:, and other non-system drives
- **Diskpart:** Safe operations allowed, dangerous patterns blocked
- **Registry Operations:** Write/delete blocked on critical paths

## Installation

### Prerequisites
- Python 3.10 or newer
- Administrator privileges (for elevated operations)

### Setup
1. Clone the repository or copy the project files to your machine.
2. (Optional) Create and activate a virtual environment:
	```powershell
	python -m venv .venv
	.\.venv\Scripts\activate
	```
3. Install dependencies:
	```powershell
	pip install -r requirements.txt
	```
	Or, if using `pyproject.toml`:
	```powershell
	pip install .
	```

## Usage

### Starting the Server
Run the MCP server with administrator privileges for full functionality:
```powershell
# Run as Administrator
python cmd_mcp.py
```

### Example Commands

#### System Information
```python
# Get comprehensive system info
mcp_shell_stream.start(command="hostname & whoami & systeminfo")

# Check DNS configuration  
mcp_shell_stream.start(command="netsh interface ip show dns")

# View network interfaces
mcp_shell_stream.start(command="netsh interface show interface")
```

#### Safe Administrative Operations
```python
# Change DNS to Google DNS
mcp_shell_stream.start(command='netsh interface ip set dns "Ethernet" static 8.8.8.8')

# Restart computer
mcp_shell_stream.start(command="Restart-Computer", shell="powershell")

# Rename computer (requires restart)
mcp_shell_stream.start(command='Rename-Computer -NewName "NEW-PC" -Force', shell="powershell")
```

#### Disk Operations (Non-System Drives)
```python
# Format external drive (E: allowed, C:/D: blocked)
mcp_shell_stream.start(command="format E: /fs:NTFS /q")

# Safe diskpart operations
mcp_shell_stream.start(command="diskpart")  # Opens diskpart console
```

#### Security Testing
```python
# Test if a command would be blocked (without executing)
mcp_shell_stream.test_security(test_command="format C:")
# Returns: would_be_allowed: False, reason: "BLOCKED: Format command targeting protected drive C:"

mcp_shell_stream.test_security(test_command="format E:")  
# Returns: would_be_allowed: True, reason: "Command appears safe"
```

## Security Configuration

### Protected Drives
The following drives are protected from format operations:
- **C:** - System drive  
- **D:** - Main data drive

### Critical Services (Cannot be stopped)
- winlogon, csrss, lsass (authentication)
- services, rpcss (core Windows services)
- dhcp, dnscache (networking)
- eventlog, cryptsvc (system/security)

### Dangerous Command Patterns (Blocked)
- Boot configuration changes (bcdedit, bootrec)
- System file manipulation in Windows directories
- Critical process termination
- Dangerous diskpart operations (clean, select disk 0)

## API Reference

### Tools Available

#### `start(command, shell=None, cwd=None)`
Execute a command with automatic security filtering.
- **Returns:** Session info or security violation error
- **Security:** All commands are pre-filtered for safety

#### `read(session_id, offset=0, max_bytes=65536)`
Read output from a running command session.
- **Returns:** Output chunk and continuation metadata

#### `status(session_id)`
Get current status of a command session.
- **Returns:** Running state, return code, timestamps

#### `stop(session_id)`  
Terminate a running command session.
- **Returns:** Termination status and logging info

#### `test_security(test_command)`
Test a command against security filters without execution.
- **Returns:** Safety assessment and reasoning

## Configuration Files

### Claude Desktop Integration
Add to your `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "shell-stream": {
      "command": "C:\\Users\\[username]\\.local\\bin\\uv.EXE",
      "args": [
        "run",
        "--with",
        "mcp[cli]",
        "mcp",
        "run",
        "D:\\path\\to\\MCP_CMD\\cmd_mcp.py"
      ]
    }
  }
}
```

## Security Logs

The server maintains security logs at:
- **Windows:** `%TEMP%\\mcp-shell-security.log`
- **Format:** `[timestamp] ACTION: command - reason`

Example log entries:
```
[2025-09-08 15:30:45] APPROVED: hostname - Command appears safe
[2025-09-08 15:31:02] BLOCKED: format C: - BLOCKED: Format command targeting protected drive C:
[2025-09-08 15:31:15] APPROVED: Restart-Computer - Command appears safe
```

## Version History

### v2.0.0 (September 8, 2025) - Security Enhanced
- ✅ **Added comprehensive security filtering system**
- ✅ **Protected system drives (C:, D:) from format operations**
- ✅ **Allowed conditional disk operations on external drives**
- ✅ **Implemented smart diskpart filtering**
- ✅ **Added security testing tool (`test_security`)**
- ✅ **Enhanced audit logging with detailed command analysis**
- ✅ **Documented all security restrictions with explanations**
- ✅ **Removed restart/shutdown command blocks (now allowed)**
- ✅ **Added drive-specific protection for format commands**

### v1.0.0 (Original)
- Basic shell command execution
- Cross-platform support
- Session management
- Real-time output streaming

## Warnings & Security Notice

- **🔒 Administrator Privileges:** Full functionality requires running as administrator
- **🛡️ Security Filtering:** Commands are automatically filtered for safety
- **📝 Audit Trail:** All operations are logged for security review
- **⚠️ Responsibility:** Always verify commands before execution
- **🚫 System Protection:** Critical system areas are protected from modification
- **💾 Data Safety:** Main drives (C:, D:) are protected from formatting

## Troubleshooting

### Common Issues

**Command Blocked by Security:**
- Use `test_security("your_command")` to understand why
- Check if command affects protected drives or system files
- Consider alternative approaches for blocked operations

**Permission Denied:**
- Ensure running as Administrator
- Check UAC settings
- Verify user has necessary privileges

**Network Operations Fail:**
- Check interface names with `netsh interface show interface`
- Verify DNS server addresses
- Ensure network adapter is enabled

## Contributing

Contributions are welcome! Please ensure any modifications maintain security standards and include appropriate filtering for dangerous operations.

## License

MIT License

## Author

**Original:** Kilgor  
**Security Enhanced Version:** Enhanced with comprehensive safety features (September 2025)

---
*This MCP server provides powerful system administration capabilities with built-in safety measures to prevent accidental system damage while maintaining administrative functionality.*
