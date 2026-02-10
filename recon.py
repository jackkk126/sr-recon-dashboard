import sys
import socket
import requests
from concurrent.futures import ThreadPoolExecutor

if len(sys.argv) < 2:
    print("Usage: python recon.py <domain>")
    sys.exit()

target = sys.argv[1]
print("Target:", target)

try:
    ip = socket.gethostbyname(target)
    print("IP Address:", ip)
except:
    print("Could not resolve domain.")
    sys.exit()

ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 8080]

print("\nScanning ports...")

open_ports = []

def scan_port(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)

    result = s.connect_ex((ip, port))
    if result == 0:
        print(f"Port {port} is OPEN")
        open_ports.append(port)

    s.close()

with ThreadPoolExecutor(max_workers=50) as executor:
    executor.map(scan_port, ports)

if not open_ports:
    print("No common ports open.")

# ---------------- SUBDOMAIN SCAN ----------------

print("\nFinding subdomains...")

found_subdomains = []

try:
    with open("wordlist.txt") as file:
        subdomains = file.read().splitlines()
except:
    print("wordlist.txt not found!")
    sys.exit()

def check_subdomain(sub):
    domain = f"{sub}.{target}"
    try:
        socket.gethostbyname(domain)
        print("Found:", domain)
        found_subdomains.append(domain)
    except:
        pass

with ThreadPoolExecutor(max_workers=50) as executor:
    executor.map(check_subdomain, subdomains)

if not found_subdomains:
    print("No subdomains found.")

# ---------------- DIRECTORY SCAN ----------------

print("\nFinding directories...")

directories = [
    "admin",
    "login",
    "dashboard",
    "api",
    "test",
    "dev",
    "backup"
]

found_dirs = []

def check_directory(dir):
    url = f"http://{target}/{dir}"
    try:
        r = requests.get(url, timeout=2)
        if r.status_code < 400:
            print("Found:", url)
            found_dirs.append(url)
    except:
        pass

with ThreadPoolExecutor(max_workers=20) as executor:
    executor.map(check_directory, directories)

if not found_dirs:
    print("No common directories found.")
import sys
import socket
import requests
from concurrent.futures import ThreadPoolExecutor

if len(sys.argv) < 2:
    print("Usage: python recon.py <domain>")
    sys.exit()

target = sys.argv[1]
print("Target:", target)

try:
    ip = socket.gethostbyname(target)
    print("IP Address:", ip)
except:
    print("Could not resolve domain.")
    sys.exit()

ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 8080]

print("\nScanning ports...")

open_ports = []

def scan_port(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)

    result = s.connect_ex((ip, port))
    if result == 0:
        print(f"Port {port} is OPEN")
        open_ports.append(port)

    s.close()

with ThreadPoolExecutor(max_workers=50) as executor:
    executor.map(scan_port, ports)

if not open_ports:
    print("No common ports open.")

# ---------------- SUBDOMAIN SCAN ----------------

print("\nFinding subdomains...")

found_subdomains = []

try:
    with open("wordlist.txt") as file:
        subdomains = file.read().splitlines()
except:
    print("wordlist.txt not found!")
    sys.exit()

def check_subdomain(sub):
    domain = f"{sub}.{target}"
    try:
        socket.gethostbyname(domain)
        print("Found:", domain)
        found_subdomains.append(domain)
    except:
        pass

with ThreadPoolExecutor(max_workers=50) as executor:
    executor.map(check_subdomain, subdomains)

if not found_subdomains:
    print("No subdomains found.")

# ---------------- DIRECTORY SCAN ----------------

print("\nFinding directories...")

directories = [
    "admin",
    "login",
    "dashboard",
    "api",
    "test",
    "dev",
    "backup"
]

found_dirs = []

def check_directory(dir):
    url = f"http://{target}/{dir}"
    try:
        r = requests.get(url, timeout=2)
        if r.status_code < 400:
            print("Found:", url)
            found_dirs.append(url)
    except:
        pass

with ThreadPoolExecutor(max_workers=20) as executor:
    executor.map(check_directory, directories)

if not found_dirs:
    print("No common directories found.")


# ---------------- TECHNOLOGY DETECTION ----------------

import requests

print("\nDetecting technologies...")

tech_found = []

try:
    response = requests.get(f"http://{target}", timeout=3)
    headers = response.headers
    content = response.text.lower()

    # Server detection
    server = headers.get("Server")
    if server:
        print("Server:", server)
        tech_found.append("Server: " + server)

    # Common tech hints
    if "wordpress" in content:
        tech_found.append("WordPress detected")
    if "wp-content" in content:
        tech_found.append("WordPress detected")
    if "php" in content:
        tech_found.append("PHP detected")
    if "laravel" in content:
        tech_found.append("Laravel detected")
    if "django" in content:
        tech_found.append("Django detected")
    if "node.js" in content:
        tech_found.append("Node.js detected")

    for tech in tech_found:
        print("Detected:", tech)

except:
    print("Technology detection failed.")

if not tech_found:
    print("No technology detected.")


# ---------------- SECURITY HEADER CHECK ----------------

print("\nChecking security headers...")

important_headers = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Referrer-Policy"
]

try:
    response = requests.get(f"http://{target}", timeout=3)
    headers = response.headers

    missing_headers = []

    for header in important_headers:
        if header in headers:
            print(f"{header}: Present")
        else:
            print(f"{header}: Missing")
            missing_headers.append(header)

    if missing_headers:
        print("Potential security improvement needed.")

except:
    print("Header check failed.")


# ---------------- SENSITIVE FILE CHECK ----------------

print("\nChecking sensitive files...")

sensitive_paths = [
    ".env",
    ".git",
    ".git/config",
    "backup.zip",
    "backup.sql",
    "db.sql",
    "config.php",
    ".htaccess",
    ".htpasswd",
    "web.config"
]

found_sensitive = []

def check_sensitive(path):
    url = f"http://{target}/{path}"
    try:
        r = requests.get(url, timeout=2)
        if r.status_code == 200:
            print("Exposed:", url)
            found_sensitive.append(url)
    except:
        pass

with ThreadPoolExecutor(max_workers=20) as executor:
    executor.map(check_sensitive, sensitive_paths)

if not found_sensitive:
    print("No sensitive files exposed.")

# ---------------- LOGIN PANEL DETECTION ----------------

print("\nSearching for login panels...")

login_paths = [
    "login",
    "admin",
    "admin/login",
    "administrator",
    "wp-admin",
    "user/login",
    "dashboard/login"
]

found_login = []

def check_login(path):
    url = f"http://{target}/{path}"
    try:
        r = requests.get(url, timeout=2)
        if r.status_code < 400:
            print("Login panel found:", url)
            found_login.append(url)
    except:
        pass

with ThreadPoolExecutor(max_workers=20) as executor:
    executor.map(check_login, login_paths)

if not found_login:
    print("No login panels found.")


# ---------------- RISK SCORE ----------------

risk_score = 0

# Ports risk
risk_score += len(open_ports) * 5

risky_ports = [21, 23, 3306, 445]
for p in open_ports:
    if p in risky_ports:
        risk_score += 15

# Subdomain exposure
risk_score += len(found_subdomains) * 3

# Directory exposure
risk_score += len(found_dirs) * 10

# limit score
if risk_score > 100:
    risk_score = 100

security_score = 100 - risk_score
if security_score < 0:
    security_score = 0

print("\nSecurity Score:", security_score, "/ 100")

if security_score > 80:
    print("Status: Good security")
elif security_score > 50:
    print("Status: Medium risk")
else:
    print("Status: High risk")

# ---------------- VAPT SUGGESTIONS ----------------

print("\nVAPT Analysis Suggestions:")

suggestions = []

# Login panels
if found_login:
    suggestions.append("Login panel found → Test for brute-force & weak passwords.")

# Admin directories
if any("admin" in d for d in found_dirs):
    suggestions.append("Admin directory exposed → Test access control.")

# WordPress
if any("WordPress" in t for t in tech_found):
    suggestions.append("WordPress detected → Check plugins & login security.")

# Sensitive files
if found_sensitive:
    suggestions.append("Sensitive files exposed → Data leakage risk.")

# Many ports
if len(open_ports) > 3:
    suggestions.append("Multiple ports open → Service attack surface high.")

if suggestions:
    for s in suggestions:
        print("-", s)
else:
    print("No major attack surface hints found.")


# ---------------- SAVE RESULTS ----------------

print("\nSaving results...")

filename = f"results_{target}.txt"

with open(filename, "w") as f:
    f.write(f"Target: {target}\n")
    f.write(f"IP: {ip}\n\n")

    f.write("Open Ports:\n")
    for port in open_ports:
        f.write(str(port) + "\n")

    f.write("\nSubdomains:\n")
    for sub in found_subdomains:
        f.write(sub + "\n")

    f.write("\nDirectories:\n")
    for d in found_dirs:
        f.write(d + "\n")

print("Results saved to", filename)

# ---------------- HTML REPORT ----------------

html_report = f"""
<html>
<head>
<title>Recon Report - {target}</title>
<style>
body {{ font-family: Arial; background:#111; color:#eee; padding:20px; }}
h1 {{ color:#4CAF50; }}
section {{ margin-bottom:20px; }}
ul {{ background:#222; padding:10px; }}
</style>
</head>

<body>
<h1>Recon Report: {target}</h1>

<section>
<h2>Target Info</h2>
<p>IP Address: {ip}</p>
<p>Security Score: {security_score}/100</p>
</section>

<section>
<h2>Open Ports</h2>
<ul>
{''.join(f"<li>{p}</li>" for p in open_ports)}
</ul>
</section>

<section>
<h2>Subdomains</h2>
<ul>
{''.join(f"<li>{s}</li>" for s in found_subdomains)}
</ul>
</section>

<section>
<h2>Directories</h2>
<ul>
{''.join(f"<li>{d}</li>" for d in found_dirs)}
</ul>
</section>

<section>
<h2>Technologies</h2>
<ul>
{''.join(f"<li>{t}</li>" for t in tech_found)}
</ul>
</section>

<section>
<h2>Sensitive Files</h2>
<ul>
{''.join(f"<li>{f}</li>" for f in found_sensitive)}
</ul>
</section>

<section>
<h2>Login Panels</h2>
<ul>
{''.join(f"<li>{l}</li>" for l in found_login)}
</ul>
</section>

</body>
</html>
"""

report_file = f"report_{target}.html"

with open(report_file, "w", encoding="utf-8") as f:
    f.write(html_report)

print("HTML report generated:", report_file)

# ---------------- PARAMETER DISCOVERY ----------------

print("\nDiscovering parameters...")

import re

found_params = set()

try:
    r = requests.get(f"http://{target}", timeout=3)
    links = re.findall(r'href=["\'](.*?)["\']', r.text)

    for link in links:
        if target in link and "?" in link and "=" in link:

            if any(x in link for x in [".css", ".js", ".png", ".jpg", ".woff", ".svg"]):
                continue

            if link.startswith("/"):
                link = f"http://{target}{link}"

            found_params.add(link)

    if found_params:
        for p in found_params:
            print("Parameter endpoint:", p)
    else:
        print("No useful parameters found.")

except:
    print("Parameter discovery failed.")
