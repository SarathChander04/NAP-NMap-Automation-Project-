## 🔐 NMap Automation Project (NAP) – Vulnerability Assessment Tool

NAP is a Python-based **Vulnerability Assessment (VA)** tool that performs:

- Port scanning
- Service enumeration
- Exploit identification using ExploitDB
- Basic remediation suggestions

This tool is built for **internal network security assessments** and does **not** perform any penetration testing or exploit execution.

---

### 🧠 Features

- 🔍 **Ping sweep scanning** to identify live hosts in a subnet (supports `-Pn` for hidden hosts)
- ⚡ **All-port scanning** and **service/version detection** using `nmap`
- 🧬 **Exploit lookup** from a local clone of [ExploitDB](https://gitlab.com/exploit-database/exploitdb)
- 📋 **Remediation recommendations** for commonly vulnerable services
- 📄 Output saved in `scan_report.csv`
- 💡 Lightweight & Offline-capable (once CSV is downloaded)

---

### 🛠️ Installation

#### 1. Clone the Repo (Sparse Checkout for ExploitDB CSV)

```bash
git clone --filter=blob:none --no-checkout https://gitlab.com/exploit-database/exploitdb.git exploitdb
cd exploitdb
git sparse-checkout init --cone
git sparse-checkout set files_exploits.csv
git checkout
```

#### 2. Install Dependencies

```bash
pip install python-nmap
```

Ensure `nmap` is installed and accessible from your command line. You can download it from: 👉 [https://nmap.org/download.html](https://nmap.org/download.html)

---

### 🚀 Usage

```bash
python main.py
```

Choose between:

- `s` – Scan a **single IP**
- `p` – Perform a **ping sweep on a subnet**, then:
  - Scan a single system
  - Scan all live hosts
  - Or exit

#### 📄 Output

Results are saved in:

```
scan_report.csv
```

Each row includes:

- IP, Port, Service, Version
- Matching Exploits (up to 3 per service)
- Suggested Remediation (if available)

---

### 📦 Updating ExploitDB CSV

The tool auto-pulls the latest version on every run. To update manually:

```bash
git -C ./exploitdb pull
```

> Only `files_exploits.csv` is checked out — no exploit code or binaries are downloaded.

---

### ⚠️ Limitations & Future Improvements

- ❌ Does not execute exploits (VA only)
- 🔍 Only checks for known services in remediation dictionary
- ↻ Exploit verification status not marked (ExploitDB does not flag them)
- 🌐 Could integrate more sources like Vulners or CVEDetails in future
- 📄 Optional: Save raw Nmap XML or TXT output for manual PT

---

### 📚 Project Credits

Developed by: **Gopanaboyina Koti Sarath Chander**\
Department of Computer Science & Engineering\
BVRIT Narsapur

