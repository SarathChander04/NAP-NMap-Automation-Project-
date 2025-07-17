# CVE-NAP (Network Analysis Project)

This script performs the following tasks:

1. **Host Discovery**: Uses `nmap` to find live hosts in a subnet or target IP.
2. **Port Scanning**: Enumerates open ports and running services with version info.
3. **CVE Lookup**: For each open service, queries the CIRCL CVE API to retrieve relevant CVEs.
4. **CSV Output**: Saves all scan and CVE info into `cve_report.csv`.

## Dependencies
```
pip install python-nmap requests
```

## Usage
Run the script and follow prompts to scan a single IP or subnet.

```
python cve_nap.py
```
Output will be saved to `cve_report.csv`.
