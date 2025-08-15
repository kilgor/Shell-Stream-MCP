# MCP Shell-Stream Server

## Overview

MCP Shell-Stream Server is a Python-based server that allows you to run, monitor, and control long-lived shell commands programmatically. It supports both Windows and Unix systems, providing real-time output streaming, session management, and remote command execution via the Model Context Protocol (MCP).

## Features

- Start long-running shell commands in isolated sessions
- Stream command output in real time
- Check status and return codes of running processes
- Terminate processes safely
- Cross-platform support (Windows, Linux, macOS)
- Retrieve system information (e.g., IP configuration)


## Installation

### Standard MCP Shell-Stream Server (`cmd_mcp.py`)
1. Clone the repository or copy the project files to your machine.
2. Ensure you have Python 3.10 or newer installed.
3. (Optional) Create and activate a virtual environment:
	```powershell
	python -m venv .venv
	.\.venv\Scripts\activate
	```
4. Install dependencies:
	```powershell
	pip install -r requirements.txt
	```
	Or, if using `pyproject.toml`:
	```powershell
	pip install .
	```

### Admin MCP Shell-Stream Server (`cmd_mcp_admin.py`)
1. Follow steps 1-4 above.
2. **Important:** Run the server with administrative rights:
	- On Windows: Right-click your terminal and select "Run as administrator" before starting the server.
	- On Unix: Use `sudo python cmd_mcp_admin.py`.


## Usage

Run the MCP server:
```powershell
python cmd_mcp.py
```

### Example: Start a Shell Command

You can use the MCP tools to start a command, read its output, check status, and stop it. For example, to restart your computer in 15 seconds:

```python
mcp_shell_stream.start(command="shutdown /r /t 15", shell="powershell")
```

### Example: Get IP Configuration

```python
mcp_shell_stream.start(command="ipconfig /all", shell="powershell")
```

### Example: Abort Shutdown

```python
mcp_shell_stream.start(command="shutdown /a", shell="powershell")
```


## Warnings & Security Notice

- **Danger:** The admin server (`cmd_mcp_admin.py`) can execute privileged commands (e.g., rename computer, restart system). Use only in trusted environments.
- **Permissions:** Some commands (like renaming the computer or restarting VS Code) require administrative rights. If not run as admin, these commands will fail.
- **Responsibility:** Always verify commands before running them, especially if exposed to remote or automated control.

## License

MIT License

## Author

Kilgor
