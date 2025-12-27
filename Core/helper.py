"""
Enhanced help system with documentation for all commands including in-memory execution
"""
from tabulate import tabulate
from .color import cyan, yellow, red, green, blue


def help():
    data = [
        [cyan("help"), yellow("Displays the help menu.")],
        [cyan("help {option}"), yellow("Displays the help menu for the specified option.")],
        [cyan("clear"), yellow("Clears the terminal.")],
        [cyan("listener"), yellow("Manage listeners (start, stop, list, load).")],
        [cyan("implant"), yellow("Generate implants (powershell, csharp).")],
        [cyan("interact"), yellow("Interact with an active agent.")],
        [cyan("agents"), yellow("List all registered agents with status.")],
        [cyan("broadcast"), yellow("Send command to all active agents.")],
        [cyan("list {option}"), yellow("List items (listener, implant, module).")],
        [cyan("exit"), yellow("Exit the application.")]
    ]
    return tabulate(data, headers=[red("Command"), red("Description")], tablefmt="fancy_grid")


def list_listener_option():
    data = [
        [cyan("http"), yellow("This listener runs under HTTP protocol.")],
        [cyan("https"), yellow("This listener runs under HTTPS protocol (planned).")],
    ]
    return tabulate(data, headers=[red("Protocol"), red("Description")], tablefmt="fancy_grid")


def list_implant_lang():
    data = [
        [cyan("powershell"), yellow("PowerShell implant with in-memory execution support.")],
        [cyan("csharp"), yellow("C# implant with .NET assembly execution support.")]
    ]
    return tabulate(data, headers=[red("Language"), red("Description")], tablefmt="fancy_grid")


def help_listener():
    data = [
        [cyan("listener start"), yellow("listener start <name> <IP> <port>")],
        [cyan("listener stop"), yellow("listener stop <name>")],
        [cyan("listener load"), yellow("listener load (reload listeners from DB)")],
        [cyan("listener list"), yellow("listener list (show active listeners)")]
    ]
    return tabulate(data, headers=[red("Action"), red("Example")], tablefmt="fancy_grid")


def help_implant():
    data = [
        [cyan("implant generate"), yellow("implant generate <listener> <lang> <name>")],
        [cyan("implant list"), yellow("implant list (show active implants)")],
        [cyan("implant remove"), yellow("implant remove <name>")]
    ]
    return tabulate(data, headers=[red("Action"), red("Example")], tablefmt="fancy_grid")


def help_interact():
    data = [
        [cyan("interact"), yellow("interact <agent_name>")]
    ]
    return tabulate(data, headers=[red("Action"), red("Example")], tablefmt="fancy_grid")


def help_interact2():
    """Comprehensive interact session help menu"""
    
    # Basic Commands
    basic_cmds = [
        [cyan("help"), yellow("Display this help menu")],
        [cyan("back"), yellow("Return to main menu (keeps agent alive)")],
        [cyan("exit / kill"), yellow("Terminate the agent")],
        [cyan("status"), yellow("Show agent status and info")],
        [cyan("clear"), yellow("Clear pending task queue")],
        [cyan("results"), yellow("Check for pending results")]
    ]
    
    # Shell Commands
    shell_cmds = [
        [cyan("cmd <command>"), yellow("Execute command via cmd.exe")],
        [cyan("powershell <cmd>"), yellow("Execute via powershell.exe")],
        [cyan("powerpick <script>"), yellow("Execute PS without powershell.exe process")],
        [cyan("inline <script>"), yellow("Execute PowerShell in-process")]
    ]
    
    # In-Memory Execution
    inmem_cmds = [
        [cyan("execute-assembly <path> [args]"), yellow("Load and run .NET assembly in memory")],
        [cyan("shellcode <path>"), yellow("Execute shellcode in current process")],
        [cyan("shinject <pid> <path>"), yellow("Inject shellcode into remote process")],
        [cyan("spawn [process]"), yellow("Spawn new process (default: notepad.exe)")],
        [cyan("inject <pid>"), yellow("Inject into existing process")]
    ]
    
    # File Operations
    file_cmds = [
        [cyan("download <remote_path>"), yellow("Download file from target")],
        [cyan("upload <local> <remote>"), yellow("Upload file to target")]
    ]
    
    # Recon Commands
    recon_cmds = [
        [cyan("sysinfo / info"), yellow("Get system information")],
        [cyan("ps / processes"), yellow("List running processes")]
    ]
    
    # Utility Commands
    util_cmds = [
        [cyan("sleep <seconds>"), yellow("Change beacon interval")],
        [cyan("module <name>"), yellow("Load and execute a module")],
        [cyan("list module"), yellow("List available modules")]
    ]
    
    output = "\n"
    output += green("=== Basic Commands ===") + "\n"
    output += tabulate(basic_cmds, headers=[red("Command"), red("Description")], tablefmt="simple") + "\n\n"
    
    output += green("=== Shell Execution ===") + "\n"
    output += tabulate(shell_cmds, headers=[red("Command"), red("Description")], tablefmt="simple") + "\n\n"
    
    output += green("=== In-Memory Execution (No Disk Touch) ===") + "\n"
    output += tabulate(inmem_cmds, headers=[red("Command"), red("Description")], tablefmt="simple") + "\n\n"
    
    output += green("=== File Operations ===") + "\n"
    output += tabulate(file_cmds, headers=[red("Command"), red("Description")], tablefmt="simple") + "\n\n"
    
    output += green("=== Reconnaissance ===") + "\n"
    output += tabulate(recon_cmds, headers=[red("Command"), red("Description")], tablefmt="simple") + "\n\n"
    
    output += green("=== Utility ===") + "\n"
    output += tabulate(util_cmds, headers=[red("Command"), red("Description")], tablefmt="simple") + "\n"
    
    return output


def help_agents():
    data = [
        [cyan("agents"), yellow("List all agents with status")],
        [cyan("agents active"), yellow("List only active agents")],
        [cyan("agents kill <name>"), yellow("Kill/remove an agent")],
        [cyan("broadcast <cmd>"), yellow("Send command to all active agents")]
    ]
    return tabulate(data, headers=[red("Action"), red("Description")], tablefmt="fancy_grid")


def help_execute_assembly():
    """Detailed help for execute-assembly command"""
    info = """
{title}

The execute-assembly command loads and executes a .NET assembly entirely in memory,
without writing to disk. This is useful for running tools like:
- Seatbelt, SharpHound, Rubeus, SafetyKatz
- Any compiled .NET executable

{usage}
  execute-assembly <path_to_assembly> [arguments]

{examples}
  execute-assembly C:\\tools\\Seatbelt.exe -group=all
  execute-assembly C:\\tools\\SharpHound.exe -c All
  execute-assembly C:\\tools\\Rubeus.exe triage

{notes}
  - Assembly is downloaded to agent memory, never touches disk
  - Arguments are passed to the assembly's Main method
  - Console output is captured and returned
  - Works with both PowerShell and C# implants
""".format(
        title=green("=== Execute-Assembly Command ==="),
        usage=yellow("Usage:"),
        examples=yellow("Examples:"),
        notes=yellow("Notes:")
    )
    return info


def help_shellcode():
    """Detailed help for shellcode execution commands"""
    info = """
{title}

Shellcode execution commands allow running raw shellcode in memory.

{cmd1}
  Execute shellcode in the current agent process.
  Usage: shellcode <path_to_shellcode_file>
  Example: shellcode C:\\payloads\\beacon.bin

{cmd2}
  Inject shellcode into a remote process.
  Usage: shinject <pid> <path_to_shellcode>
  Example: shinject 1234 C:\\payloads\\beacon.bin

{notes}
  - Shellcode file should be raw bytes (not base64 encoded)
  - For shinject, target process must be accessible
  - Use 'ps' command to find process IDs
""".format(
        title=green("=== Shellcode Execution Commands ==="),
        cmd1=yellow("shellcode:"),
        cmd2=yellow("shinject:"),
        notes=yellow("Notes:")
    )
    return info


def banner_text():
    """Return the main banner"""
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║    ██████╗ ██╗   ██╗██████╗ ████████╗ ██████╗██████╗         ║
    ║   ██╔════╝ ██║   ██║██╔══██╗╚══██╔══╝██╔════╝╚════██╗        ║
    ║   ██║  ███╗██║   ██║██████╔╝   ██║   ██║      █████╔╝        ║
    ║   ██║   ██║██║   ██║██╔═══╝    ██║   ██║     ██╔═══╝         ║
    ║   ╚██████╔╝╚██████╔╝██║        ██║   ╚██████╗███████╗        ║
    ║    ╚═════╝  ╚═════╝ ╚═╝        ╚═╝    ╚═════╝╚══════╝        ║
    ║                                                              ║
    ║            [ S T E A L T H   M O D E ]                       ║
    ║   Command & Control Framework v2.0                           ║
    ║   Hidden | Silent | Deadly                                   ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    return banner
