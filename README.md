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

## Security Notice

Be cautious when running system-level commands, especially those that affect system state (shutdown, restart). Ensure the server is used in a trusted environment.

## License

MIT License

## Author

Kilgor
