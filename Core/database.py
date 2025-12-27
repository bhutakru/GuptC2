"""
Enhanced database module with multi-agent tracking support
"""
import sqlite3
import random
import string
from datetime import datetime


def connect():
    try:
        conn = sqlite3.connect("database.db", check_same_thread=False)
        # Ensure tables exist
        init_tables(conn)
        return conn
    except:
        print("[-] Cannot find the database!!")
        exit()


def init_tables(conn):
    """Initialize all required tables"""
    cursor = conn.cursor()
    
    # Listener table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS Listener (
            Listener_Name TEXT PRIMARY KEY,
            Listener_IP TEXT,
            Listener_Port TEXT,
            Listener_Token TEXT UNIQUE
        )
    ''')
    
    # Enhanced Implant table with more tracking fields
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS Implant_Info (
            Implant_Name TEXT PRIMARY KEY,
            Implant_Key TEXT,
            Listener_Name TEXT,
            Listener_Port TEXT,
            Listener_IP TEXT,
            Active INTEGER DEFAULT 0,
            Implant_OldName TEXT
        )
    ''')
    
    # Add new columns if they don't exist (for upgrading old databases)
    new_columns = [
        ("Hostname", "TEXT"),
        ("Username", "TEXT"),
        ("LocalIPs", "TEXT"),
        ("OS_Info", "TEXT"),
        ("PID", "TEXT"),
        ("First_Seen", "TEXT"),
        ("Last_Seen", "TEXT"),
        ("Sleep_Time", "INTEGER DEFAULT 5")
    ]
    
    for col_name, col_type in new_columns:
        try:
            cursor.execute(f"ALTER TABLE Implant_Info ADD COLUMN {col_name} {col_type}")
        except:
            pass  # Column already exists
    
    # Modules table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS modules (
            Module_Name TEXT PRIMARY KEY,
            Module_Description TEXT,
            Module_Path TEXT
        )
    ''')
    
    # Task history table for logging
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS Task_History (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            Implant_Name TEXT,
            Task TEXT,
            Task_Time TEXT,
            Result TEXT,
            Result_Time TEXT
        )
    ''')
    
    conn.commit()


def start_listener(connector, listener_ip, listener_port, listener_name):
    letters = string.ascii_lowercase
    Token = ''.join(random.choice(letters) for i in range(32))

    try:
        connector.cursor()
        connector.execute(
            "INSERT INTO Listener(Listener_Name,Listener_IP,Listener_Port,Listener_Token) VALUES(?,?,?,?)",
            (listener_name, listener_ip, listener_port, Token)
        )
        connector.commit()
        return True
    except sqlite3.Error as error:
        print("[-] Cannot record the listener in the database!!")
        print(error)
        return False


def delete_listener(connector, listener_token):
    try:
        connector.cursor()
        connector.execute("DELETE FROM Listener WHERE Listener_Token=?", (listener_token,))
        connector.commit()
        return True
    except:
        print("[-] Cannot delete the listener!!")
        return False


def return_token(connector, listener_name):
    try:
        connector.cursor()
        results = connector.execute(
            "SELECT Listener_Token, Listener_IP, Listener_Port FROM Listener WHERE Listener_Name=?",
            (listener_name,)
        )
        results = results.fetchall()
        return results
    except:
        print("[-] Cannot retrieve the token!!")
        return False


def check_token(connector, listener_name, listener_token):
    try:
        connector.cursor()
        results = connector.execute(
            "SELECT Listener_Token FROM Listener WHERE Listener_Name=?",
            (listener_name,)
        )
        results = results.fetchall()
        if results[0][0] == listener_token:
            return True
        return False
    except:
        print("[-] Cannot retrieve the token!!")
        return False


def list_listener(connector):
    try:
        connector.cursor()
        results = connector.execute("SELECT Listener_Name, Listener_IP, Listener_Port FROM Listener")
        results = results.fetchall()
        return results
    except:
        print("[-] Cannot retrieve the Active Listener")
        return False


def run_listener(connector):
    try:
        connector.cursor()
        results = connector.execute("SELECT Listener_IP,Listener_Port FROM Listener")
        results = results.fetchall()
        return results
    except:
        print("[-] Cannot retrieve previous listeners!!")
        return False


def clear_database(connector):
    try:
        connector.cursor()
        connector.execute("DELETE FROM Listener")
        connector.commit()
        connector.execute("DELETE FROM Implant_Info")
        connector.commit()
        connector.execute("DELETE FROM Task_History")
        connector.commit()
        return True
    except:
        print("[-] Cannot delete the old listeners")
        return False


def Save_Implant(name):
    """Mark implant as active when it checks in"""
    try:
        connect_db = sqlite3.connect("database.db", check_same_thread=False)
        connect_db.cursor()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Update active status and last seen
        connect_db.execute(
            "UPDATE Implant_Info SET Active=1, Last_Seen=? WHERE Implant_Name=?",
            (now, name)
        )
        connect_db.commit()
        return True
    except:
        pass
    return False


def Update_Implant_Info(name, hostname=None, username=None, local_ips=None, os_info=None, pid=None):
    """Update detailed implant information"""
    try:
        connect_db = sqlite3.connect("database.db", check_same_thread=False)
        cursor = connect_db.cursor()
        
        updates = []
        values = []
        
        if hostname:
            updates.append("Hostname=?")
            values.append(hostname)
        if username:
            updates.append("Username=?")
            values.append(username)
        if local_ips:
            updates.append("LocalIPs=?")
            values.append(local_ips)
        if os_info:
            updates.append("OS_Info=?")
            values.append(os_info)
        if pid:
            updates.append("PID=?")
            values.append(pid)
        
        if updates:
            values.append(name)
            query = f"UPDATE Implant_Info SET {', '.join(updates)} WHERE Implant_Name=?"
            cursor.execute(query, values)
            connect_db.commit()
        
        return True
    except Exception as e:
        print(f"Error updating implant info: {e}")
        return False


def list_implant(conn):
    conn.cursor()
    results = conn.execute("SELECT Implant_Name FROM Implant_Info WHERE Active='1'")
    results = results.fetchall()
    return results


def list_all_implants(conn):
    """List all implants with detailed info - backward compatible"""
    conn.cursor()
    try:
        # Try new schema first
        results = conn.execute("""
            SELECT Implant_Name, Active, Hostname, Username, LocalIPs, Last_Seen, Sleep_Time 
            FROM Implant_Info
        """)
        results = results.fetchall()
        return results
    except:
        # Fallback to basic schema
        results = conn.execute("SELECT Implant_Name, Active FROM Implant_Info")
        results = results.fetchall()
        # Return with None placeholders for missing columns
        return [(r[0], r[1], None, None, None, None, 5) for r in results]


def rec_implant(conn, implant_name, key, listener_name, listener_ip, listener_port):
    conn.cursor()
    try:
        # Try with new schema (First_Seen column)
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn.execute("""
            INSERT INTO Implant_Info(Implant_Name, Implant_Key, Listener_Name, Listener_Port, Listener_IP, First_Seen) 
            VALUES(?,?,?,?,?,?)
        """, (implant_name, key, listener_name, listener_port, listener_ip, now))
    except:
        # Fallback to old schema (no First_Seen column)
        conn.execute("""
            INSERT INTO Implant_Info(Implant_Name, Implant_Key, Listener_Name, Listener_Port, Listener_IP) 
            VALUES(?,?,?,?,?)
        """, (implant_name, key, listener_name, listener_port, listener_ip))
    conn.commit()
    return True


def return_key(connect, name):
    connect.cursor()
    results = connect.execute("SELECT Implant_Key FROM Implant_Info WHERE Implant_Name=?", (name,))
    results = results.fetchall()
    return results


def ChangeImplantName(connect, old_name, name):
    try:
        connect.cursor()
        connect.execute(
            "UPDATE Implant_Info SET Implant_OldName=? WHERE Implant_Name=?",
            (old_name, old_name)
        )
        connect.commit()
        connect.execute(
            "UPDATE Implant_Info SET Implant_Name=? WHERE Implant_OldName=?",
            (name, old_name)
        )
        connect.commit()
        return True
    except:
        return False


def list_module(connect):
    try:
        connect.cursor()
        results = connect.execute("SELECT Module_Name,Module_Description,Module_Path FROM modules")
        results = results.fetchall()
        return results
    except:
        return False


def return_rename_key(connect, name):
    connect.cursor()
    results = connect.execute("SELECT Implant_Key FROM Implant_Info WHERE Implant_OldName=?", (name,))
    results = results.fetchall()
    return results


def Delete_Active_Implant(connect, name):
    connect.cursor()
    connect.execute("DELETE FROM Implant_Info WHERE Implant_Name=?", (name,))
    connect.commit()
    return True


def log_task(conn, implant_name, task):
    """Log a task sent to an implant"""
    try:
        cursor = conn.cursor()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute(
            "INSERT INTO Task_History(Implant_Name, Task, Task_Time) VALUES(?,?,?)",
            (implant_name, task, now)
        )
        conn.commit()
        return cursor.lastrowid
    except:
        return None


def log_result(conn, task_id, result):
    """Log result for a task"""
    try:
        cursor = conn.cursor()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute(
            "UPDATE Task_History SET Result=?, Result_Time=? WHERE id=?",
            (result, now, task_id)
        )
        conn.commit()
        return True
    except:
        return False


def get_implant_details(conn, name):
    """Get detailed information about an implant"""
    try:
        cursor = conn.cursor()
        result = cursor.execute("""
            SELECT Implant_Name, Listener_Name, Listener_IP, Listener_Port,
                   Active, Hostname, Username, LocalIPs, OS_Info, PID,
                   First_Seen, Last_Seen, Sleep_Time
            FROM Implant_Info WHERE Implant_Name=?
        """, (name,)).fetchone()
        
        if result:
            return {
                'name': result[0],
                'listener_name': result[1],
                'listener_ip': result[2],
                'listener_port': result[3],
                'active': bool(result[4]),
                'hostname': result[5],
                'username': result[6],
                'local_ips': result[7],
                'os_info': result[8],
                'pid': result[9],
                'first_seen': result[10],
                'last_seen': result[11],
                'sleep_time': result[12]
            }
    except:
        pass
    return None


def update_sleep_time(conn, name, sleep_time):
    """Update implant sleep time"""
    try:
        cursor = conn.cursor()
        cursor.execute("UPDATE Implant_Info SET Sleep_Time=? WHERE Implant_Name=?", (sleep_time, name))
        conn.commit()
        return True
    except:
        return False
