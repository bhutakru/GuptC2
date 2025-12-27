<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey.svg" alt="Platform">
  <img src="https://img.shields.io/badge/License-Educational-red.svg" alt="License">
  <img src="https://img.shields.io/badge/Version-2.0-green.svg" alt="Version">
</p>

<h1 align="center">
  <br>
  🥷 GuptC2 - Command & Control Framework
  <br>
</h1>

<h4 align="center">A stealthy, multi-agent C2 framework with in-memory execution capabilities. "Gupt" means "Hidden" in Hindi.</h4>

<p align="center">
  <a href="#-features">Features</a> •
  <a href="#-installation">Installation</a> •
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-usage">Usage</a> •
  <a href="#-screenshots">Screenshots</a> •
  <a href="#-architecture">Architecture</a> •
  <a href="#%EF%B8%8F-disclaimer">Disclaimer</a>
</p>

---

```
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
```

---

## ✨ Features

### 🎯 Core Capabilities
| Feature | Description |
|---------|-------------|
| **Multi-Agent Support** | Handle multiple concurrent agent connections with individual session management |
| **In-Memory Task Queues** | Tasks are queued in memory for fast, disk-less operations |
| **AES-256-CBC Encryption** | All communications are encrypted with unique keys per agent |
| **Cross-Platform Implants** | Generate PowerShell and C# implants |
| **Real-time Results** | Instant result retrieval with callback system |

### 🔧 Implant Features
| Feature | PowerShell | C# |
|---------|:----------:|:--:|
| Command Execution | ✅ | ✅ |
| In-Memory Assembly | ✅ | ✅ |
| Shellcode Execution | ✅ | ✅ |
| Process Injection | ✅ | ✅ |
| AMSI/ETW Bypass | ✅ | ❌ |
| File Operations | ✅ | ✅ |
| System Recon | ✅ | ✅ |

### 🛡️ Evasion Techniques
- **AMSI Bypass** - PowerShell implant patches `amsi.dll` at runtime
- **ETW Bypass** - Patches `ntdll!EtwEventWrite` to disable event tracing
- **Dynamic API Resolution** - Avoids static imports through reflection
- **Indirect Execution** - Uses ScriptBlock creation to avoid direct `IEX`
- **User-Agent Randomization** - Mimics legitimate browser traffic
- **Jitter** - Randomized beacon intervals (15-35% variance)

---

## 📦 Installation

### Prerequisites
- Python 3.8+
- .NET SDK 8.0+ (for C# implants)
- PowerShell 5.1+ (for PowerShell implants)

### Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/GuptC2-V2.0.git
cd GuptC2-V2.0

# Install Python dependencies
pip install -r requirements.txt

# Run the framework
python run.py
```

### Dependencies
```
flask>=2.0.0
requests>=2.25.0
tabulate>=0.9.0
colorama>=0.4.4
pycryptodome>=3.15.0
psutil>=5.9.0
```

---

## 🚀 Quick Start

### 1️⃣ Start GuptC2
```bash
python run.py
```

### 2️⃣ Create a Listener
```
[Gupt@C2]::> listener start http 192.168.1.100 8080
```

### 3️⃣ Generate an Implant
```
[Gupt@C2]::> implant generate http csharp agent1
```

### 4️⃣ Compile & Execute on Target
```bash
# Navigate to implant directory
cd data/implant/agent1

# Compile
dotnet build -c Release

# Execute on target (the .exe file)
./bin/Release/net8.0/agent1.exe
```

### 5️⃣ Interact with Agent
```
[Gupt@C2]::> interact agent1
[Gupt@C2]-->[Agent:agent1]::> sysinfo
[Gupt@C2]-->[Agent:agent1]::> cmd whoami
```

---

## 📖 Usage

### Main Menu Commands

| Command | Description |
|---------|-------------|
| `help` | Display help menu |
| `help <command>` | Help for specific command |
| `listener` | Manage listeners |
| `implant` | Generate implants |
| `interact <name>` | Interact with an agent |
| `agents` | List all agents |
| `broadcast <cmd>` | Send command to all agents |
| `clear` | Clear terminal |
| `exit` | Exit GuptC2 |

### Listener Commands

```bash
# Start a new HTTP listener
listener start <name> <ip> <port>

# Example
listener start http 0.0.0.0 8080

# Stop a listener
listener stop <name>

# List active listeners
listener list

# Reload listeners from database
listener load
```

### Implant Commands

```bash
# Generate implant
implant generate <listener> <language> <name>

# Examples
implant generate http powershell ps_agent
implant generate http csharp cs_agent

# List implants
implant list

# Remove implant
implant remove <name>
```

### Agent Interaction Commands

Once you've run `interact <agent_name>`:

#### 🖥️ Basic Commands
| Command | Description |
|---------|-------------|
| `help` | Show interact help menu |
| `back` | Return to main menu |
| `exit` / `kill` | Terminate the agent |
| `status` | Show agent status |
| `clear` | Clear task queue |
| `results` | Check pending results |

#### 💻 Shell Execution
| Command | Description |
|---------|-------------|
| `cmd <command>` | Execute via cmd.exe |
| `powershell <cmd>` | Execute via powershell.exe |
| `powerpick <script>` | Execute PS without spawning powershell.exe |
| `inline <script>` | Execute PowerShell in-process |

#### 🧠 In-Memory Execution
| Command | Description |
|---------|-------------|
| `execute-assembly <path> [args]` | Load .NET assembly in memory |
| `shellcode <path>` | Execute shellcode in current process |
| `shinject <pid> <path>` | Inject shellcode into remote process |
| `spawn [process]` | Spawn new process (default: notepad.exe) |
| `inject <pid>` | Inject into existing process |

#### 📁 File Operations
| Command | Description |
|---------|-------------|
| `download <remote_path>` | Download file from target |
| `upload <local> <remote>` | Upload file to target |

#### 🔍 Reconnaissance
| Command | Description |
|---------|-------------|
| `sysinfo` / `info` | Get system information |
| `ps` / `processes` | List running processes |

#### ⚙️ Utility
| Command | Description |
|---------|-------------|
| `sleep <seconds>` | Change beacon interval |
| `module <name>` | Load a PowerShell module |
| `list module` | List available modules |

---

## 📸 Screenshots

### Main Interface
![Main Menu](screenshots/main_menu.png)
*GuptC2 main console with available commands*

### Listener Management
![Listener](screenshots/listener.png)
*Starting and managing HTTP listeners*

### Implant Generation
![Implant](screenshots/implant_gen.png)
*Generating C# and PowerShell implants*

### Agent Interaction
![Interact](screenshots/interact.png)
*Interacting with active agents and executing commands*

### System Information
![Sysinfo](screenshots/sysinfo.png)
*Gathering target system information*

### Multi-Agent Management
![Agents](screenshots/agents.png)
*Managing multiple concurrent agent sessions*

> 📌 **Note:** Add your own screenshots to the `screenshots/` folder

---

## 🏗️ Architecture

```
GuptC2/
├── 📄 run.py                    # Main entry point
├── 📄 requirements.txt          # Python dependencies
├── 📄 database.db               # SQLite database
│
├── 📁 Core/                     # Core modules
│   ├── agentmanager.py          # Multi-agent session handler
│   ├── color.py                 # Terminal colors
│   ├── database.py              # Database operations
│   ├── encryption.py            # AES-256-CBC encryption
│   ├── helper.py                # Help menus
│   ├── implanthandler.py        # Legacy handler
│   └── listener.py              # Flask HTTP listener
│
├── 📁 functions/                # Command handlers
│   ├── banner.py                # ASCII banner
│   ├── implantfunctions.py      # Implant generation
│   ├── interactfunctions.py     # Agent interaction
│   ├── listenerfunctions.py     # Listener management
│   └── main.py                  # Main command loop
│
├── 📁 Implants/                 # Implant templates
│   ├── csharp_template.cs       # C# implant source
│   └── powershell.ps1           # PowerShell implant
│
└── 📁 data/                     # Generated data
    └── 📁 implant/              # Generated implants
        └── 📁 <agent_name>/     # Per-agent files
            ├── implant.cs       # Generated source
            ├── tasks.enc        # Encrypted tasks
            └── result.dec       # Decrypted results
```

### Communication Flow

```
┌─────────────────┐                    ┌─────────────────┐
│                 │    1. Check-in     │                 │
│     IMPLANT     │ ─────────────────► │    LISTENER     │
│    (Target)     │                    │   (GuptC2)      │
│                 │ ◄───────────────── │                 │
│                 │   2. Encrypted     │                 │
│                 │      Tasks         │                 │
│                 │                    │                 │
│                 │ ─────────────────► │                 │
│                 │   3. Encrypted     │                 │
│                 │      Results       │                 │
└─────────────────┘                    └─────────────────┘
         │                                      │
         │           AES-256-CBC                │
         │         Encrypted Channel            │
         └──────────────────────────────────────┘
```

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Health check |
| `/record/<name>` | POST | Agent registration |
| `/beacon/<name>` | GET | Task polling |
| `/task/<name>` | GET | Task retrieval (legacy) |
| `/result/<name>` | POST | Result submission |
| `/assembly/<name>` | GET | Assembly download |
| `/shellcode/<name>` | GET | Shellcode download |
| `/module/<name>` | GET | PS module download |
| `/upload/<name>` | POST | File upload |

---

## 🔒 Security Features

### Encryption
- **Algorithm:** AES-256-CBC
- **Key Size:** 256 bits (32 bytes)
- **IV:** Randomly generated for each message
- **Key Generation:** Cryptographically secure random bytes

### Agent Security
- Unique encryption key per agent
- No hardcoded credentials
- Encrypted task queue
- Secure result transmission

---

## 🛠️ Adding Custom Modules

1. Create a PowerShell script in your modules directory
2. Register it in the database:

```python
# In Python console or script
from Core import database
conn = database.connect()
conn.execute(
    "INSERT INTO modules(Module_Name, Module_Description, Module_Path) VALUES(?,?,?)",
    ("MyModule", "Description of module", "/path/to/module.ps1")
)
conn.commit()
```

3. Use in interact session:
```
[Agent:agent1]::> module MyModule
```

---

## 📋 Todo / Roadmap

- [ ] HTTPS listener support
- [ ] Domain fronting
- [ ] Malleable C2 profiles
- [ ] Pivoting capabilities
- [ ] Credential harvesting modules
- [ ] Persistence modules
- [ ] Web interface
- [ ] API for automation

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## ⚠️ Disclaimer

<table>
<tr>
<td>

**🚨 LEGAL NOTICE**

This tool is provided for **authorized security testing and educational purposes only**.

- ✅ Use only on systems you own or have explicit written permission to test
- ✅ Ensure compliance with all applicable local, state, and federal laws
- ✅ Obtain proper authorization before conducting any security assessments
- ❌ Do NOT use for unauthorized access to computer systems
- ❌ Do NOT use for malicious purposes

**The developer assumes no liability for misuse of this software.**

By using this tool, you agree to use it responsibly and ethically.

</td>
</tr>
</table>

---

## 📄 License

This project is for educational purposes only. Use responsibly.

---

## 👤 Author

**Rushabh Bhutak**

- GitHub: [@yourusername](https://github.com/yourusername)

---

<p align="center">
  <b>⭐ Star this repo if you find it useful! ⭐</b>
</p>

<p align="center">
  Made with ❤️ for the security community
</p>
