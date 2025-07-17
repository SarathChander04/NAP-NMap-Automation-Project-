import nmap
import csv
import re
import subprocess
import os
from pathlib import Path

# Configuration
CSV_FOLDER = Path("./exploitdb")
EXPLOIT_DB_PATH = CSV_FOLDER / "files_exploits.csv"
MAX_EXPLOITS_PER_SERVICE = 3
OUTPUT_CSV = "scan_report.csv"
GIT_REPO = "https://gitlab.com/exploit-database/exploitdb.git"

def setup_sparse_checkout():
    if not CSV_FOLDER.exists():
        print("[⏬] Cloning only files_exploits.csv using sparse-checkout...")
        subprocess.run(["git", "clone", "--filter=blob:none", "--no-checkout", GIT_REPO, str(CSV_FOLDER)], check=True)
        subprocess.run(["git", "-C", str(CSV_FOLDER), "sparse-checkout", "init", "--cone"], check=True)
        subprocess.run(["git", "-C", str(CSV_FOLDER), "sparse-checkout", "set", "files_exploits.csv"], check=True)
        subprocess.run(["git", "-C", str(CSV_FOLDER), "checkout"], check=True)
        print("[✔] Sparse checkout complete.")
    else:
        print("[✔] Repo already initialized. Skipping setup.")

def update_exploitdb_csv():
    print("[🔄] Updating files_exploits.csv ...")
    result = subprocess.run(["git", "-C", str(CSV_FOLDER), "pull"], capture_output=True, text=True)
    if "Already up to date" in result.stdout:
        print("[✔] CSV is already up to date.")
    else:
        print("[✔] CSV updated.")

def normalize(text):
    return re.sub(r'[^a-z0-9]+', '', text.lower())

def load_exploit_db():
    if not EXPLOIT_DB_PATH.exists():
        print(f"[!] Exploit DB CSV not found at {EXPLOIT_DB_PATH}")
        return []
    with open(EXPLOIT_DB_PATH, newline='', encoding='utf-8-sig', errors='ignore') as csvfile:
        reader = csv.DictReader(csvfile)
        rows = []
        for row in reader:
            row = {k.strip().lower(): v for k, v in row.items()}
            rows.append(row)
        print(f"[DEBUG] Loaded {len(rows)} exploits with normalized keys.")
        return rows

def get_remediation(product, port, service):
    remediation_lookup = {
        ("vsftpd", 21): "Use vsftpd version 3.0.5 or later.",
        ("openssh", 22): "Update to OpenSSH 9.7p1 or higher.",
        ("postfix", 25): "Use Postfix 3.9 or later.",
        ("bind", 53): "Use BIND 9.18.24 or later.",
        ("apache", 80): "Update to Apache 2.4.59 or later.",
        ("mysql", 3306): "Use MySQL 8.4 or later.",
        ("postgresql", 5432): "Use PostgreSQL 16.3 or later.",
        ("telnet", 23): "Disable Telnet. Use SSH instead.",
        ("apachetomcat", 8180): "Update to Tomcat 10.1.23 or later.",
        ("apachejserv", 8009): "Disable AJP or patch connector.",
        ("rpcbind", 111): "Use rpcbind version 1.2.6 or later and restrict access via firewall.",
        ("netbios", 139): "Disable NetBIOS over TCP/IP unless needed. Harden Samba config.",
        ("samba", 445): "Update Samba to 4.20 or later and restrict access via firewall.",
        ("login", 513): "Disable rlogin service. Use SSH instead.",
        ("shell", 514): "Disable rsh service. Use SSH instead.",
        ("exec", 512): "Disable rexec service or use secure alternatives.",
        ("distccd", 3632): "Disable distccd if not needed or restrict access by IP.",
        ("java-rmi", 1099): "Update JRE and use secure RMI with authentication. Block external RMI access.",
        ("java-rmi", 46111): "Update JRE and use secure RMI with authentication. Block external RMI access.",
        ("bindshell", 1524): "Remove bindshell and investigate for backdoors.",
        ("nfs", 2049): "Restrict NFS exports and update to latest stable version.",
        ("mountd", 51009): "Update to latest rpc.mountd and limit to trusted IPs.",
        ("nlockmgr", 54787): "Restrict access and update nfs-utils to 2.6.4 or later.",
        ("status", 36126): "Disable or firewall RPC info exposure. Use rpc.statd >= 2.6.4.",
        ("drb", 8787): "Avoid exposing Ruby DRb to external networks. Use firewalls or SSH tunnels.",
        ("X11", 6000): "Disable X11 forwarding or restrict to localhost using -nolisten tcp.",
        ("irc", 6667): "Update to UnrealIRCd 6.1.4+ and harden server config.",
        ("irc", 6697): "Update to UnrealIRCd 6.1.4+ and harden server config.",
        ("vnc", 5900): "Update to latest VNC server and use strong passwords + tunneling.",
        ("ccproxyftp", 2121): "Avoid CCProxy FTP or update to patched version.",
    }

    norm_product = normalize(product)
    norm_service = normalize(service)

    for (alias, expected_port), advice in remediation_lookup.items():
        if (alias in norm_product or alias in norm_service) and expected_port == port:
            return advice

    return "No standard remediation found. Manual review recommended."


def find_exploits(product, version, exploits, service=""):
    matches = []
    product_norm = normalize(product)
    version_norm = normalize(version)
    service_norm = normalize(service)

    identifiers = set(filter(None, [product_norm, service_norm]))

    aliases = {
        'postfix': ['smtp', 'postfix'],
        'apachetomcat': ['tomcat', 'jsp', 'coyote'],
        'openssh': ['openssh', 'ssh'],
        'vsftpd': ['ftp', 'vsftpd'],
        'apache': ['apache', 'httpd'],
        'bind': ['bind', 'domain', 'dns'],
        'mysql': ['mysql'],
        'postgresql': ['postgresql', 'pgsql', 'postgres'],
        'telnet': ['telnet', 'telnetd'],
        'ajp': ['ajp', 'jserv'],
        'rpcbind': ['rpcbind', 'portmapper'],
        'samba': ['netbios', 'smb', 'samba'],
        'login': ['rlogin', 'login'],
        'shell': ['rsh', 'shell'],
        'exec': ['rexec', 'exec'],
        'distccd': ['distccd'],
        'vnc': ['vnc'],
        'irc': ['irc'],
        'nfs': ['nfs'],
        'mountd': ['mountd'],
        'nlockmgr': ['nlockmgr'],
        'status': ['status'],
        'drb': ['drb'],
        'x11': ['x11']
    }

    all_keywords = set()
    for ident in identifiers:
        for key, vals in aliases.items():
            if key in ident:
                all_keywords.update(vals)
    if not all_keywords:
        all_keywords.update(identifiers)

    for entry in exploits:
        desc = entry.get('description', '')
        if not desc:
            continue
        desc_norm = normalize(desc)

        keyword_hit = any(kw in desc_norm for kw in all_keywords)
        version_hit = version_norm in desc_norm or version_norm[:3] in desc_norm or version_norm[:1] in desc_norm

        if keyword_hit and (version_hit or not version_norm):
            matches.append({'description': desc})
        if len(matches) >= MAX_EXPLOITS_PER_SERVICE:
            break
    return matches

def write_to_csv(rows):
    with open(OUTPUT_CSV, "w", newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=[
            "IP", "Port", "Service", "Version", "Remediation", "Exploits"
        ])
        writer.writeheader()
        for row in rows:
            del row["CVEs"]
            writer.writerow(row)

def scan_host(ip):
    nm = nmap.PortScanner()
    print(f"[⚡] Scanning {ip} for all ports...")
    nm.scan(hosts=ip, arguments="-p- -sV")
    result = []
    for proto in nm[ip].all_protocols():
        ports = nm[ip][proto].keys()
        for port in ports:
            service = nm[ip][proto][port]
            result.append({
                "port": port,
                "service": service.get("name", ""),
                "product": service.get("product", ""),
                "version": service.get("version", "")
            })
    return result

def ping_sweep(subnet):
    print(f"[🔍] Performing ping sweep on {subnet} (with -Pn)...")
    result = subprocess.run(["nmap", "-sn", "-Pn", subnet], capture_output=True, text=True)
    return re.findall(r"Nmap scan report for (\d+\.\d+\.\d+\.\d+)", result.stdout)

def main():
    setup_sparse_checkout()
    update_exploitdb_csv()
    exploit_db = load_exploit_db()

    mode = input("Scan mode - single (s) or subnet ping sweep (p)? ").lower()
    if mode == 's':
        targets = [input("Enter IP address to scan: ").strip()]
    elif mode == 'p':
        subnet = input("Enter subnet (e.g., 192.168.1.0/24): ")
        targets = ping_sweep(subnet)
        print("\n[+] Live hosts detected:")
        for idx, ip in enumerate(targets):
            print(f"  [{idx}] {ip}")

        choice = input("\nScan a host (index), all (a), or quit (q)? ").lower()
        if choice == 'a':
            pass
        elif choice.isdigit() and int(choice) < len(targets):
            targets = [targets[int(choice)]]
        else:
            print("[✖] Quitting...")
            return
    else:
        print("[✖] Invalid choice.")
        return

    results = []
    for ip in targets:
        services = scan_host(ip)
        for svc in services:
            port = svc["port"]
            product = svc["product"]
            version = svc["version"]
            service = svc["service"]
            remediation = get_remediation(product, port, service)
            found_exploits = find_exploits(product, version, exploit_db, service)
            exploit_desc = [e['description'] for e in found_exploits]
            results.append({
                "IP": ip,
                "Port": port,
                "Service": service,
                "Version": version,
                "Remediation": remediation,
                "Exploits": "; ".join(exploit_desc),
                "CVEs": ""
            })

    write_to_csv(results)
    print(f"[✔] Report saved to {OUTPUT_CSV}")

if __name__ == "__main__":
    main()
