"""Subprocess execution helper for external security tools."""

import subprocess
import shutil
import tempfile
import os
from dataclasses import dataclass


class ToolNotFoundError(Exception):
    """Raised when a required tool is not found in PATH."""
    pass


class ToolExecutionError(Exception):
    """Raised when a tool execution fails."""
    pass


@dataclass
class CommandResult:
    """Result of a command execution."""
    stdout: str
    stderr: str
    return_code: int
    command: list[str]

    @property
    def success(self) -> bool:
        return self.return_code == 0


REQUIRED_TOOLS = ["nmap", "ffuf", "sqlmap"]
OPTIONAL_TOOLS = ["java"]  # For Burp Suite


def check_tool_exists(tool: str) -> bool:
    """Check if a tool exists in PATH."""
    return shutil.which(tool) is not None


def check_required_tools() -> list[str]:
    """Check all required tools are installed.

    Returns:
        List of missing tools (empty if all present).
    """
    missing = [t for t in REQUIRED_TOOLS if not check_tool_exists(t)]
    return missing


def check_all_tools() -> dict[str, bool]:
    """Check availability of all tools.

    Returns:
        Dict mapping tool name to availability.
    """
    all_tools = REQUIRED_TOOLS + OPTIONAL_TOOLS
    return {tool: check_tool_exists(tool) for tool in all_tools}


def run_command(
    cmd: list[str],
    timeout: int = 300,
    check: bool = False,
    cwd: str | None = None,
) -> CommandResult:
    """Run external command and capture output.

    Args:
        cmd: Command and arguments as list.
        timeout: Timeout in seconds (default 5 minutes).
        check: If True, raise exception on non-zero exit.
        cwd: Working directory for the command.

    Returns:
        CommandResult with stdout, stderr, and return code.

    Raises:
        ToolNotFoundError: If the tool is not in PATH.
        ToolExecutionError: If check=True and command fails.
        subprocess.TimeoutExpired: If command times out.
    """
    tool = cmd[0]

    # Check if tool exists
    if not check_tool_exists(tool):
        raise ToolNotFoundError(f"{tool} not found in PATH. Install it first.")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
        )

        cmd_result = CommandResult(
            stdout=result.stdout,
            stderr=result.stderr,
            return_code=result.returncode,
            command=cmd,
        )

        if check and not cmd_result.success:
            raise ToolExecutionError(
                f"Command failed with exit code {result.returncode}: {' '.join(cmd)}\n"
                f"stderr: {result.stderr}"
            )

        return cmd_result

    except subprocess.TimeoutExpired:
        raise ToolExecutionError(f"Command timed out after {timeout}s: {' '.join(cmd)}")


def run_command_async(
    cmd: list[str],
    cwd: str | None = None,
) -> subprocess.Popen:
    """Start a command without waiting for completion.

    Args:
        cmd: Command and arguments as list.
        cwd: Working directory for the command.

    Returns:
        Popen object for the running process.
    """
    tool = cmd[0]

    if not check_tool_exists(tool):
        raise ToolNotFoundError(f"{tool} not found in PATH")

    return subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=cwd,
    )


def get_temp_file(suffix: str = ".txt") -> str:
    """Get a temporary file path.

    Args:
        suffix: File extension.

    Returns:
        Path to temporary file.
    """
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.close(fd)
    return path


def get_temp_dir() -> str:
    """Get a temporary directory path.

    Returns:
        Path to temporary directory.
    """
    return tempfile.mkdtemp()
