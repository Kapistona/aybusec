#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
siem-detective  —  egitim amacli log analiz / dedektif araci
=============================================================

Tek dosya, SIFIR harici bagimlilik (saf Python stdlib). Heterojen bir SIEM
ham log'unu (nginx / sshd / firewall / Windows / DNS / auditd / sudo) okur,
her atak sinifi icin bir DEDEKTOR calistirir, bulgulari MITRE ATT&CK'e
esler ve bir saldiri zaman cizelgesi (incident timeline) kurar.

Kullanim:
    python3 analyze.py siem_sample.log
    python3 analyze.py siem_sample.log --json rapor.json
    python3 analyze.py siem_sample.log --only ssh_bruteforce,data_exfil
    python3 analyze.py siem_sample.log --check          # cevap anahtari ile dogrula
    python3 analyze.py siem_sample.log --vt             # bulgulardaki IP'leri VirusTotal'de sorgula
    python3 analyze.py --vt --ip 8.8.8.8 --hash <sha256>   # tek atis IOC sorgusu

VirusTotal icin ucretsiz API anahtari:  export VT_API_KEY=xxxx

Yeni bir kural eklemek = @detector ile isaretli yeni bir fonksiyon yazmak.
Ogrenci icin giris noktasi budur.
"""

import argparse
import json
import os
import re
import sys
import time
import urllib.request
import urllib.error
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta

# ===========================================================================
# AYARLAR  (ogrenci bunlari degistirerek hassasiyeti ayarlasin)
# ===========================================================================
CONFIG = {
    "ssh_fail_threshold": 15,       # bir IP'den N basarisiz SSH -> brute-force
    "ssh_window_sec": 300,          # ... su pencere icinde
    "win_fail_threshold": 20,       # Windows 4625 esigi
    "portscan_distinct_ports": 40,  # tek kaynaktan N farkli port -> tarama
    "portscan_window_sec": 120,
    "scanner_hits_threshold": 10,   # tarayici UA'dan N istek
    "dns_tunnel_queries": 20,       # bir domaine N+ TXT/uzun-label sorgu
    "dns_tunnel_label_len": 30,     # en soldaki etiket bu kadar uzunsa supheli
    "exfil_bytes_threshold": 10_000_000,   # 10 MB tek akista -> exfil supheli
    "impossible_travel_min": 60,    # ayni kullanici, N dk icinde farkli ulke
    "evidence_samples": 3,          # her bulguda gosterilecek ornek ham satir
}

# IP -> ulke (egitim icin kucuk statik tablo; gercekte GeoIP veritabani kullanin)
GEO = {
    "185.220.101.47": "DE", "45.33.22.18": "US", "103.76.228.9": "IN",
    "193.27.14.201": "RU", "159.203.44.77": "US", "91.219.236.14": "RU",
    "212.102.63.5": "NL", "5.188.206.19": "RU",
    "78.40.125.9": "TR", "198.51.100.23": "US",
}

def geo(ip):
    """Cok kaba ulke cozumu — sadece egitim icin."""
    if ip is None:
        return "?"
    if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.16."):
        return "LAN"
    if ip in GEO:
        return GEO[ip]
    if ip.startswith("88."):   # ornek veri setindeki mesru TR araligi
        return "TR"
    return "??"

# ===========================================================================
# RENKLER  (stdlib, bagimlilik yok; --no-color ile kapatilir)
# ===========================================================================
class C:
    RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
    RED = "\033[31m"; GRN = "\033[32m"; YEL = "\033[33m"
    BLU = "\033[34m"; MAG = "\033[35m"; CYN = "\033[36m"

    @classmethod
    def off(cls):
        for k in list(vars(cls)):
            if k.isupper():
                setattr(cls, k, "")

SEV_COLOR = {"critical": C.MAG, "high": C.RED, "medium": C.YEL,
             "low": C.CYN, "info": C.DIM}
SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# ===========================================================================
# OLAY MODELI
# ===========================================================================
@dataclass
class Event:
    ts: datetime
    host: str
    source: str            # normalize kaynak: web/ssh/firewall/windows/dns/auditd/sudo/unknown
    raw: str
    src_ip: str = None
    dst_ip: str = None
    user: str = None
    method: str = None
    url: str = None
    status: int = None
    size: int = None
    ua: str = None
    event_id: str = None
    action: str = None     # ALLOW/DROP/Failed/Accepted...
    proto: str = None
    dpt: int = None
    nbytes: int = None
    flags: str = None
    domain: str = None
    qtype: str = None
    command: str = None
    image: str = None
    parent: str = None
    fhash: str = None
    signed: str = None

@dataclass
class Finding:
    detector: str
    title: str
    severity: str
    confidence: str
    mitre: str
    first_seen: datetime
    last_seen: datetime
    entities: dict
    count: int
    evidence: list = field(default_factory=list)

    def to_dict(self):
        return {
            "detector": self.detector, "title": self.title,
            "severity": self.severity, "confidence": self.confidence,
            "mitre": self.mitre,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "entities": self.entities, "count": self.count,
            "evidence": self.evidence,
        }

# ===========================================================================
# PARSER  (ham satir -> Event)
# ===========================================================================
HEADER_RE = re.compile(r"^(\S+) (\S+) (\S+?): (.*)$")
PROG_RE = re.compile(r"\[\d+\]$")

NGINX_RE = re.compile(
    r'^(\S+) - - "(\S+) (\S+) HTTP/[\d.]+" (\d+) (\d+) "[^"]*" "([^"]*)"')
SSH_FAIL_RE = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+) port")
SSH_INVALID_RE = re.compile(r"Invalid user (\S+) from (\S+)")
SSH_OK_RE = re.compile(r"Accepted (?:password|publickey) for (\S+) from (\S+) port")
FW_RE = re.compile(r"\[FW (ALLOW|DROP)\]")
KV_RE = re.compile(r"(\w+)=(\S+)")
DNS_RE = re.compile(r"query: (\S+) IN (\S+) client (\S+)")
SUDO_RE = re.compile(r"^(\S+) : .*COMMAND=(.*)$")

PROG_SOURCE = {
    "nginx": "web", "sshd": "ssh", "kernel": "firewall",
    "Microsoft-Windows-Security-Auditing": "windows",
    "named": "dns", "auditd": "auditd", "sudo": "sudo", "edr": "edr",
}

EDR_CMD_RE = re.compile(r'CommandLine="([^"]*)"')

def parse_line(line):
    m = HEADER_RE.match(line.rstrip("\n"))
    if not m:
        return None
    ts_s, host, prog, msg = m.groups()
    prog = PROG_RE.sub("", prog)              # sshd[123] -> sshd
    try:
        ts = datetime.strptime(ts_s, "%Y-%m-%dT%H:%M:%S%z")
    except ValueError:
        return None
    source = PROG_SOURCE.get(prog, "unknown")
    ev = Event(ts=ts, host=host, source=source, raw=line.rstrip("\n"))

    if source == "web":
        mm = NGINX_RE.match(msg)
        if mm:
            ev.src_ip, ev.method, ev.url = mm.group(1), mm.group(2), mm.group(3)
            ev.status, ev.size, ev.ua = int(mm.group(4)), int(mm.group(5)), mm.group(6)

    elif source == "ssh":
        if (f := SSH_FAIL_RE.search(msg)):
            ev.action, ev.user, ev.src_ip = "Failed", f.group(1), f.group(2)
        elif (f := SSH_OK_RE.search(msg)):
            ev.action, ev.user, ev.src_ip = "Accepted", f.group(1), f.group(2)
        elif (f := SSH_INVALID_RE.search(msg)):
            ev.action, ev.user, ev.src_ip = "Invalid", f.group(1), f.group(2)

    elif source == "firewall":
        fw = FW_RE.search(msg)
        if fw:
            ev.action = fw.group(1)
            kv = dict(KV_RE.findall(msg))
            ev.src_ip, ev.dst_ip = kv.get("SRC"), kv.get("DST")
            ev.proto, ev.flags = kv.get("PROTO"), kv.get("FLAGS")
            if kv.get("DPT"): ev.dpt = int(kv["DPT"])
            if kv.get("BYTES"): ev.nbytes = int(kv["BYTES"])

    elif source == "windows":
        kv = dict(KV_RE.findall(msg))
        ev.event_id = kv.get("EventID")
        ev.user = kv.get("Account")
        ev.src_ip = kv.get("Source")
        ev.action = kv.get("Status")
        ev.command = kv.get("CommandLine")

    elif source == "dns":
        d = DNS_RE.search(msg)
        if d:
            ev.domain, ev.qtype, ev.src_ip = d.group(1), d.group(2), d.group(3)

    elif source == "auditd":
        ev.command = msg
        ev.action = "EXECVE"

    elif source == "sudo":
        s = SUDO_RE.match(msg)
        if s:
            ev.user, ev.command = s.group(1), s.group(2)

    elif source == "edr":
        cm = EDR_CMD_RE.search(msg)
        if cm:
            ev.command = cm.group(1)
        kv = dict(KV_RE.findall(EDR_CMD_RE.sub("", msg)))   # CommandLine haric alanlar
        ev.user, ev.image, ev.parent = kv.get("User"), kv.get("Image"), kv.get("Parent")
        ev.fhash, ev.signed = kv.get("Hash"), kv.get("Signed")
        ev.action = kv.get("EventType")

    return ev

def load(path):
    events, bad = [], 0
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if not line.strip():
                continue
            ev = parse_line(line)
            if ev:
                events.append(ev)
            else:
                bad += 1
    events.sort(key=lambda e: e.ts)
    return events, bad

# ===========================================================================
# DEDEKTOR ALTYAPISI
# ===========================================================================
DETECTORS = []   # (name, func)

def detector(name):
    def deco(fn):
        DETECTORS.append((name, fn))
        return fn
    return deco

def _win_count(times, window_sec):
    """Sirali zaman listesinde bir pencerede dusen max olay sayisi (kayan pencere)."""
    times = sorted(times)
    best, i = 0, 0
    for j in range(len(times)):
        while (times[j] - times[i]).total_seconds() > window_sec:
            i += 1
        best = max(best, j - i + 1)
    return best

def _samples(raws):
    return raws[:CONFIG["evidence_samples"]]

# ===========================================================================
# DEDEKTORLER  (her biri Event listesi alir, Finding listesi doner)
# ===========================================================================

@detector("ssh_bruteforce")
def d_ssh_bruteforce(events):
    """IP basina kisa surede cok sayida basarisiz SSH girisi -> ardindan basari = compromise."""
    out = []
    fails = defaultdict(list)       # ip -> [Event]
    oks = defaultdict(list)
    for e in events:
        if e.source == "ssh" and e.action in ("Failed", "Invalid"):
            fails[e.src_ip].append(e)
        elif e.source == "ssh" and e.action == "Accepted":
            oks[e.src_ip].append(e)
    for ip, evs in fails.items():
        times = [e.ts for e in evs]
        burst = _win_count(times, CONFIG["ssh_window_sec"])
        if burst < CONFIG["ssh_fail_threshold"]:
            continue
        # Ayni IP'den, basarisizliklardan SONRA gelen bir basari var mi?
        first_fail = min(times)
        success = [o for o in oks.get(ip, []) if o.ts >= first_fail]
        if success:
            s = success[0]
            out.append(Finding(
                "ssh_bruteforce",
                f"SSH brute-force -> BASARILI giris (compromise): {ip} kullanici '{s.user}'",
                "critical", "high", "T1110 - Brute Force",
                first_fail, s.ts,
                {"src_ip": ip, "user": s.user, "host": s.host, "geo": geo(ip),
                 "failed_attempts": len(evs)},
                len(evs), _samples([e.raw for e in evs] + [s.raw])))
        else:
            out.append(Finding(
                "ssh_bruteforce",
                f"SSH brute-force girisimi (basarisiz): {ip} ({len(evs)} deneme)",
                "high", "high", "T1110 - Brute Force",
                min(times), max(times),
                {"src_ip": ip, "host": evs[0].host, "geo": geo(ip)},
                len(evs), _samples([e.raw for e in evs])))
    return out

@detector("win_bruteforce")
def d_win_bruteforce(events):
    """Windows 4625 patlamasi -> 4624 basari -> 4672 ozel ayricalik (priv-esc)."""
    out = []
    fails = defaultdict(list)
    oks = defaultdict(list)
    privs = []
    for e in events:
        if e.source != "windows":
            continue
        if e.event_id == "4625":
            fails[e.src_ip].append(e)
        elif e.event_id == "4624":
            oks[e.src_ip].append(e)
        elif e.event_id == "4672":
            privs.append(e)
    for ip, evs in fails.items():
        if len(evs) < CONFIG["win_fail_threshold"]:
            continue
        first = min(e.ts for e in evs)
        success = [o for o in oks.get(ip, []) if o.ts >= first]
        sev, conf, extra = "high", "high", {}
        last = max(e.ts for e in evs)
        title = f"Windows brute-force: {ip} ({len(evs)}x EventID=4625)"
        if success:
            sev, title = "critical", title + " -> 4624 BASARILI giris"
            last = success[0].ts
            if privs:
                title += " + 4672 ozel ayricalik (priv-esc)"
        out.append(Finding(
            "win_bruteforce", title, sev, conf, "T1110 - Brute Force",
            first, last,
            {"src_ip": ip, "account": evs[0].user, "host": evs[0].host, "geo": geo(ip)},
            len(evs), _samples([e.raw for e in evs] + [s.raw for s in success[:1]])))
    return out

@detector("port_scan")
def d_port_scan(events):
    """Tek kaynaktan kisa surede cok sayida FARKLI porta (firewall DROP) = tarama."""
    out = []
    by_src = defaultdict(list)
    for e in events:
        if e.source == "firewall" and e.action == "DROP" and e.dpt is not None:
            by_src[e.src_ip].append(e)
    for ip, evs in by_src.items():
        ports = {e.dpt for e in evs}
        if len(ports) < CONFIG["portscan_distinct_ports"]:
            continue
        times = [e.ts for e in evs]
        out.append(Finding(
            "port_scan",
            f"Port taramasi: {ip} -> {len(ports)} farkli port",
            "medium", "high", "T1046 - Network Service Discovery",
            min(times), max(times),
            {"src_ip": ip, "distinct_ports": len(ports), "geo": geo(ip)},
            len(evs), _samples([e.raw for e in evs])))
    return out

# Web saldiri imzalari: (etiket, regex)
WEB_SIGS = [
    ("SQLi", re.compile(r"(union\s+select|'\s*or\s*'?1'?='?1|sleep\(|;\s*drop\s+table|'--|%20or%201=1|or%201=1)", re.I)),
    ("XSS", re.compile(r"(<script|onerror=|onload=|<svg|<img[^>]+src=x|javascript:)", re.I)),
    ("LFI/Traversal", re.compile(r"(\.\./|\.\.%2f|/etc/passwd|/etc/shadow|%00|php://|\.\.\\|/\.env|/\.git/)", re.I)),
    ("CmdInjection", re.compile(r"(;\s*cat\s|\|\s*nc\s|%7c|`.*`|\$\(|;\s*id|/bin/sh|nc%20-e|\(\)\s*{)", re.I)),
]

@detector("web_attack")
def d_web_attack(events):
    """URL (ve UA) icinde SQLi / XSS / LFI / komut enjeksiyonu imzalari."""
    out = []
    buckets = defaultdict(list)   # (ip, etiket) -> [Event]
    for e in events:
        if e.source != "web" or not e.url:
            continue
        hay = e.url + " " + (e.ua or "")
        for label, rx in WEB_SIGS:
            if rx.search(hay):
                buckets[(e.src_ip, label)].append(e)
    for (ip, label), evs in buckets.items():
        times = [e.ts for e in evs]
        mitre = {"SQLi": "T1190 - Exploit Public-Facing App",
                 "XSS": "T1059.007 - JavaScript",
                 "LFI/Traversal": "T1083 - File & Directory Discovery",
                 "CmdInjection": "T1059 - Command & Scripting Interpreter"}[label]
        sev = "high" if label in ("SQLi", "CmdInjection") else "medium"
        out.append(Finding(
            "web_attack",
            f"Web saldirisi [{label}]: {ip} ({len(evs)} istek)",
            sev, "high", mitre, min(times), max(times),
            {"src_ip": ip, "attack": label, "host": evs[0].host, "geo": geo(ip)},
            len(evs), _samples([e.raw for e in evs])))
    return out

SCANNER_UA_RE = re.compile(
    r"(sqlmap|nikto|nmap|masscan|nuclei|dirbuster|gobuster|wpscan|acunetix|\(\)\s*{\s*:;)", re.I)

@detector("scanner_ua")
def d_scanner_ua(events):
    """Bilinen tarayici / exploit araci User-Agent imzalari."""
    out = []
    by = defaultdict(list)
    for e in events:
        if e.source == "web" and e.ua and SCANNER_UA_RE.search(e.ua):
            tool = SCANNER_UA_RE.search(e.ua).group(1).lower()
            by[(e.src_ip, tool)].append(e)
    for (ip, tool), evs in by.items():
        if len(evs) < CONFIG["scanner_hits_threshold"]:
            continue
        times = [e.ts for e in evs]
        out.append(Finding(
            "scanner_ua",
            f"Otomatik tarayici tespiti: '{tool}' {ip} ({len(evs)} istek)",
            "medium", "high", "T1595 - Active Scanning",
            min(times), max(times),
            {"src_ip": ip, "tool": tool, "geo": geo(ip)},
            len(evs), _samples([e.raw for e in evs])))
    return out

@detector("dns_tunnel")
def d_dns_tunnel(events):
    """Tek domaine yuksek hacimli / uzun-etiketli / TXT sorgulari = DNS tunnel / C2."""
    out = []
    by_dom = defaultdict(list)
    for e in events:
        if e.source != "dns" or not e.domain:
            continue
        labels = e.domain.split(".")
        reg = ".".join(labels[-2:]) if len(labels) >= 2 else e.domain
        by_dom[reg].append(e)
    for dom, evs in by_dom.items():
        txt = [e for e in evs if e.qtype == "TXT"]
        long_labels = [e for e in evs
                       if e.domain.split(".")[0] and len(e.domain.split(".")[0]) >= CONFIG["dns_tunnel_label_len"]]
        if len(txt) >= CONFIG["dns_tunnel_queries"] or len(long_labels) >= CONFIG["dns_tunnel_queries"]:
            times = [e.ts for e in evs]
            out.append(Finding(
                "dns_tunnel",
                f"DNS tunnel / C2 supheli domain: {dom} ({len(evs)} sorgu, {len(txt)} TXT)",
                "high", "medium", "T1071.004 - DNS",
                min(times), max(times),
                {"domain": dom, "queries": len(evs), "txt": len(txt),
                 "client": evs[0].src_ip},
                len(evs), _samples([e.raw for e in evs])))
    return out

@detector("data_exfil")
def d_data_exfil(events):
    """Disa buyuk hacimli outbound (firewall BYTES) -> veri sizdirma supheli."""
    out = []
    by_dst = defaultdict(list)
    for e in events:
        if e.source == "firewall" and e.action == "ALLOW" and e.nbytes:
            by_dst[e.dst_ip].append(e)
    for dst, evs in by_dst.items():
        total = sum(e.nbytes for e in evs)
        big = [e for e in evs if e.nbytes >= CONFIG["exfil_bytes_threshold"]]
        if not big:
            continue
        times = [e.ts for e in evs]
        mb = total / 1_000_000
        out.append(Finding(
            "data_exfil",
            f"Veri sizdirma supheli: {evs[0].src_ip} -> {dst} ({mb:.1f} MB / {len(evs)} akis)",
            "critical", "medium", "T1048 - Exfiltration Over Alt Protocol",
            min(times), max(times),
            {"src_ip": evs[0].src_ip, "dst_ip": dst, "total_mb": round(mb, 1),
             "geo": geo(dst)},
            len(evs), _samples([e.raw for e in evs])))
    return out

@detector("impossible_travel")
def d_impossible_travel(events):
    """Ayni kullanici kisa surede farkli ulkeden giris = impossible travel / hesap ele gecirme."""
    out = []
    logins = defaultdict(list)   # user -> [(ts, ip, country)]
    for e in events:
        ok_ssh = e.source == "ssh" and e.action == "Accepted"
        ok_win = e.source == "windows" and e.event_id == "4624"
        if (ok_ssh or ok_win) and e.user and e.src_ip:
            cc = geo(e.src_ip)
            if cc in ("LAN", "?"):   # ic ag girislerini sayma
                continue
            logins[e.user].append((e.ts, e.src_ip, cc, e.raw))
    win = timedelta(minutes=CONFIG["impossible_travel_min"])
    for user, recs in logins.items():
        recs.sort()
        for a, b in zip(recs, recs[1:]):
            if a[2] != b[2] and (b[0] - a[0]) <= win:
                out.append(Finding(
                    "impossible_travel",
                    f"Impossible travel: '{user}' {a[2]}({a[1]}) -> {b[2]}({b[1]}) "
                    f"{int((b[0]-a[0]).total_seconds()//60)} dk icinde",
                    "high", "medium", "T1078 - Valid Accounts",
                    a[0], b[0],
                    {"user": user, "ip_a": a[1], "geo_a": a[2],
                     "ip_b": b[1], "geo_b": b[2]},
                    2, [a[3], b[3]]))
    return out

SUSPROC_SIGS = [
    (re.compile(r"/dev/tcp/", re.I), "Reverse shell (/dev/tcp)"),
    (re.compile(r"nc\s+-e|ncat\s+-e", re.I), "Netcat reverse shell"),
    (re.compile(r"/etc/shadow", re.I), "Hassas dosya erisimi (/etc/shadow)"),
    (re.compile(r"import\s+socket.*pty|pty\.spawn", re.I), "Python reverse shell"),
    (re.compile(r"(wget|curl)\s+https?://\d+\.\d+\.\d+\.\d+", re.I), "IP'den indirme (dropper)"),
    (re.compile(r"base64\s+-d|base64\s+--decode", re.I), "base64 cozme (obfuscation)"),
    (re.compile(r"chmod\s+\+x\s+/tmp/", re.I), "/tmp icinde calistirilabilir olusturma"),
]

@detector("suspicious_process")
def d_suspicious_process(events):
    """auditd / sudo komutlarinda reverse-shell, dropper, hassas dosya imzalari."""
    out = []
    for e in events:
        if e.source not in ("auditd", "sudo") or not e.command:
            continue
        for rx, label in SUSPROC_SIGS:
            if rx.search(e.command):
                out.append(Finding(
                    "suspicious_process",
                    f"Supheli komut [{label}] @ {e.host}"
                    + (f" (user {e.user})" if e.user else ""),
                    "critical", "high", "T1059 - Command & Scripting Interpreter",
                    e.ts, e.ts,
                    {"host": e.host, "user": e.user, "signature": label},
                    1, [e.raw]))
                break
    return out

# EDR / uc nokta imzalari: (etiket, regex, mitre, severity)
EDR_SIGS = [
    ("Encoded PowerShell", re.compile(r"-enc(odedcommand)?\s|-e\s+[A-Za-z0-9+/]{40,}", re.I),
     "T1027 - Obfuscated/Encoded", "high"),
    ("Hidden PowerShell", re.compile(r"-w(indowstyle)?\s*hidden|-nop(rofile)?\b", re.I),
     "T1059.001 - PowerShell", "medium"),
    ("Download cradle", re.compile(r"DownloadString|DownloadFile|Net\.WebClient|Invoke-WebRequest|\biwr\b|\bIEX\b", re.I),
     "T1105 - Ingress Tool Transfer", "high"),
    ("AMSI bypass", re.compile(r"AmsiUtils|amsiInitFailed", re.I),
     "T1562.001 - Disable/Modify Tools", "high"),
    ("LSASS / cred dump", re.compile(r"sekurlsa|logonpasswords|comsvcs\.dll.*MiniDump|lsass", re.I),
     "T1003.001 - LSASS Memory", "critical"),
    ("LOLBin indirme", re.compile(r"certutil.*-urlcache|bitsadmin\s+/transfer|mshta\s+http|regsvr32.*scrobj", re.I),
     "T1218 - System Binary Proxy Exec", "high"),
    ("Persistence", re.compile(r"schtasks\s+/create|reg(\.exe)?\s+add.*CurrentVersion\\Run|New-ScheduledTask", re.I),
     "T1053.005 / T1547.001 - Persistence", "high"),
]
OFFICE_PARENTS = re.compile(r"(WINWORD|EXCEL|POWERPNT|OUTLOOK)\.EXE", re.I)
SERVER_PARENTS = re.compile(r"(w3wp|sqlservr|httpd)\.exe", re.I)
CHILD_SHELL = re.compile(r"(powershell|cmd|wscript|cscript|mshta)\.exe", re.I)

@detector("edr_endpoint")
def d_edr(events):
    """EDR process telemetrisi: PowerShell obfuscation, LOLBin, cred-dump, supheli parent."""
    out = []
    for e in events:
        if e.source != "edr":
            continue
        cmd = e.command or ""
        img = e.image or ""
        # 1) komut-satiri imzalari
        for label, rx, mitre, sev in EDR_SIGS:
            if rx.search(cmd):
                ent = {"host": e.host, "user": e.user, "image": img,
                       "parent": e.parent, "signature": label}
                if e.fhash:
                    ent["hash"] = e.fhash
                if e.signed == "false":
                    ent["signed"] = "false"
                out.append(Finding(
                    "edr_endpoint", f"EDR [{label}] @ {e.host}", sev, "high", mitre,
                    e.ts, e.ts, ent, 1, [e.raw]))
        # 2) supheli parent-child (office/server dogurdugu shell)
        parent = e.parent or ""
        if (OFFICE_PARENTS.search(parent) or SERVER_PARENTS.search(parent)) and CHILD_SHELL.search(img):
            src = "Office makrosu" if OFFICE_PARENTS.search(parent) else "Sunucu/webshell"
            out.append(Finding(
                "edr_endpoint",
                f"EDR [Supheli parent: {src}] {parent} -> {img.split(chr(92))[-1]} @ {e.host}",
                "high", "high",
                "T1566 - Phishing" if OFFICE_PARENTS.search(parent) else "T1505.003 - Web Shell",
                e.ts, e.ts,
                {"host": e.host, "user": e.user, "parent": parent, "image": img},
                1, [e.raw]))
        # 3) imzasiz calistirilabilir
        if e.signed == "false" and img.lower().endswith(".exe"):
            out.append(Finding(
                "edr_endpoint", f"EDR [Imzasiz process] {img.split(chr(92))[-1]} @ {e.host}",
                "medium", "medium", "T1204 - User Execution",
                e.ts, e.ts,
                {"host": e.host, "user": e.user, "image": img,
                 **({"hash": e.fhash} if e.fhash else {})},
                1, [e.raw]))
    return out

# ===========================================================================
# ZAMAN CIZELGESI (incident timeline)  — bulgulari saldiri hikayesine dizer
# ===========================================================================
def build_timeline(findings):
    rows = sorted(findings, key=lambda f: (f.first_seen or datetime.max.replace(tzinfo=None)))
    return rows

# ===========================================================================
# VIRUSTOTAL ZENGINLESTIRME  (saf urllib)
# ===========================================================================
VT_BASE = "https://www.virustotal.com/api/v3"

def vt_query(kind, value, api_key):
    """kind: 'ip_addresses' | 'files'. Doner: dict veya hata string'i."""
    url = f"{VT_BASE}/{kind}/{value}"
    req = urllib.request.Request(url, headers={"x-apikey": api_key,
                                               "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            data = json.load(r)
        stats = data["data"]["attributes"].get("last_analysis_stats", {})
        return {
            "value": value,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "link": f"https://www.virustotal.com/gui/"
                    f"{'ip-address' if kind == 'ip_addresses' else 'file'}/{value}",
        }
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"value": value, "error": "VT'de kayit yok (muhtemelen sentetik IOC)"}
        if e.code == 401:
            return {"value": value, "error": "Gecersiz API anahtari (401)"}
        if e.code == 429:
            return {"value": value, "error": "Hiz limiti (429) - ucretsiz tier 4/dk"}
        return {"value": value, "error": f"HTTP {e.code}"}
    except Exception as e:
        return {"value": value, "error": str(e)}

def enrich_virustotal(findings, extra_ips, hashes, api_key, cap=8):
    ips = set(extra_ips)
    hset = set(hashes)
    for f in findings:
        for k in ("src_ip", "dst_ip", "ip_a", "ip_b"):
            v = f.entities.get(k)
            if v and geo(v) not in ("LAN",):
                ips.add(v)
        if f.entities.get("hash"):
            hset.add(f.entities["hash"])
    ips = sorted(ips)[:cap]
    hashes = sorted(hset)[:cap]
    results = {"ips": [], "hashes": []}
    print(f"\n{C.BOLD}VirusTotal sorgusu{C.RESET} ({len(ips)} IP, {len(hashes)} hash) "
          f"{C.DIM}[ucretsiz tier ~4/dk, araya bekleme konur]{C.RESET}")
    for i, ip in enumerate(ips):
        results["ips"].append(vt_query("ip_addresses", ip, api_key))
        if i < len(ips) - 1:
            time.sleep(15)
    for h in hashes:
        results["hashes"].append(vt_query("files", h, api_key))
        time.sleep(15)
    return results

def print_vt(results):
    def row(r):
        if "error" in r:
            return f"  {C.DIM}{r['value']:<40} {r['error']}{C.RESET}"
        m, s = r["malicious"], r["suspicious"]
        col = C.RED if m else (C.YEL if s else C.GRN)
        verdict = f"{col}malicious={m} suspicious={s}{C.RESET}"
        return f"  {r['value']:<40} {verdict}  {C.DIM}{r['link']}{C.RESET}"
    for r in results.get("ips", []):
        print(row(r))
    for r in results.get("hashes", []):
        print(row(r))

# ===========================================================================
# CEVAP ANAHTARI  (--check)  — veri setine gomulu 10 senaryo
# ===========================================================================
ANSWER_KEY = {
    "ssh_bruteforce":    "185.220.101.47",
    "win_bruteforce":    "212.102.63.5",
    "port_scan":         "193.27.14.201",
    "data_exfil":        "5.188.206.19",
    "dns_tunnel":        "exfil-c2.net",
    "impossible_travel": "caner",
    "scanner_ua":        None,          # sqlmap + nikto beklenir
    "web_attack":        None,          # SQLi/XSS/LFI/CmdInjection beklenir
    "suspicious_process": None,         # reverse shell / dropper beklenir
    "edr_endpoint":      "FIN-PC03",    # PowerShell/LOLBin/cred-dump zinciri beklenir
}

def run_check(findings):
    by_det = defaultdict(list)
    for f in findings:
        by_det[f.detector].append(f)
    print(f"\n{C.BOLD}== CEVAP ANAHTARI DOGRULAMASI =={C.RESET}")
    ok = True
    for det, needle in ANSWER_KEY.items():
        found = by_det.get(det, [])
        hit = bool(found)
        if needle:
            hit = any(needle in json.dumps(f.entities) or needle in " ".join(f.evidence)
                      for f in found)
        mark = f"{C.GRN}PASS{C.RESET}" if hit else f"{C.RED}FAIL{C.RESET}"
        ok = ok and hit
        print(f"  [{mark}] {det:<20} {'('+needle+')' if needle else ''}")
    print(f"\n  Sonuc: {(C.GRN+'TUM SENARYOLAR YAKALANDI'+C.RESET) if ok else (C.RED+'EKSIK VAR'+C.RESET)}")
    return ok

# ===========================================================================
# RAPORLAMA
# ===========================================================================
def print_report(events, bad, findings):
    print(f"{C.BOLD}== OZET =={C.RESET}")
    print(f"  Olay sayisi      : {len(events)}  (cozulemeyen: {bad})")
    src = Counter(e.source for e in events)
    print("  Kaynak dagilimi  : " + ", ".join(f"{k}={v}" for k, v in src.most_common()))
    if events:
        print(f"  Zaman araligi    : {events[0].ts}  ->  {events[-1].ts}")
    sevc = Counter(f.severity for f in findings)
    print(f"  Bulgu sayisi     : {len(findings)}  " +
          " ".join(f"{SEV_COLOR[s]}{s}={sevc.get(s,0)}{C.RESET}"
                   for s in ("critical", "high", "medium", "low", "info") if sevc.get(s)))

    print(f"\n{C.BOLD}== BULGULAR =={C.RESET}")
    for f in sorted(findings, key=lambda x: (-SEV_RANK[x.severity],
                                             x.first_seen or datetime.max.replace(tzinfo=None))):
        col = SEV_COLOR[f.severity]
        print(f"\n{col}● [{f.severity.upper():<8}]{C.RESET} {C.BOLD}{f.title}{C.RESET}")
        print(f"    {C.DIM}MITRE {f.mitre} | guven: {f.confidence} | olay: {f.count}{C.RESET}")
        ent = ", ".join(f"{k}={v}" for k, v in f.entities.items())
        print(f"    {C.DIM}{ent}{C.RESET}")
        for ev in f.evidence:
            print(f"      {C.DIM}| {ev[:140]}{C.RESET}")

    print(f"\n{C.BOLD}== INCIDENT TIMELINE =={C.RESET}")
    for f in build_timeline(findings):
        col = SEV_COLOR[f.severity]
        t = f.first_seen.strftime("%m-%d %H:%M") if f.first_seen else "??"
        print(f"  {C.DIM}{t}{C.RESET}  {col}[{f.severity[:4].upper()}]{C.RESET} {f.title}")

def run_detectors(events, only, exclude):
    findings = []
    for name, fn in DETECTORS:
        if only and name not in only:
            continue
        if exclude and name in exclude:
            continue
        findings.extend(fn(events))
    return findings

# ===========================================================================
# MAIN
# ===========================================================================
def main(argv=None):
    ap = argparse.ArgumentParser(description="Egitim amacli SIEM log dedektif araci")
    ap.add_argument("logfile", nargs="?", help="analiz edilecek log dosyasi")
    ap.add_argument("--json", metavar="DOSYA", help="bulgulari JSON olarak yaz")
    ap.add_argument("--only", help="sadece bu dedektorler (virgulle)")
    ap.add_argument("--exclude", help="bu dedektorleri atla (virgulle)")
    ap.add_argument("--list", action="store_true", help="dedektorleri listele ve cik")
    ap.add_argument("--check", action="store_true", help="cevap anahtari ile dogrula")
    ap.add_argument("--vt", action="store_true", help="IP/hash'leri VirusTotal'de sorgula")
    ap.add_argument("--ip", action="append", default=[], help="VT icin ek IP (tekrarlanabilir)")
    ap.add_argument("--hash", action="append", default=[], help="VT icin dosya hash'i (tekrarlanabilir)")
    ap.add_argument("--vt-key", help="VirusTotal API anahtari (yoksa VT_API_KEY ortam degiskeni)")
    ap.add_argument("--no-color", action="store_true", help="renkleri kapat")
    args = ap.parse_args(argv)

    if args.no_color or not sys.stdout.isatty():
        C.off()

    if args.list:
        print("Mevcut dedektorler:")
        for name, fn in DETECTORS:
            print(f"  {name:<20} {(fn.__doc__ or '').strip().splitlines()[0]}")
        return 0

    only = set(args.only.split(",")) if args.only else None
    exclude = set(args.exclude.split(",")) if args.exclude else None

    # VT-only mod (log olmadan tek atis IOC sorgusu)
    if args.vt and not args.logfile:
        key = args.vt_key or os.environ.get("VT_API_KEY")
        if not key:
            print("HATA: VT_API_KEY tanimli degil (export VT_API_KEY=... veya --vt-key).",
                  file=sys.stderr)
            return 2
        res = enrich_virustotal([], args.ip, args.hash, key)
        print_vt(res)
        return 0

    if not args.logfile:
        ap.error("log dosyasi gerekli (veya --vt --ip/--hash ile tek atis sorgu)")

    events, bad = load(args.logfile)
    findings = run_detectors(events, only, exclude)

    print_report(events, bad, findings)

    vt_results = None
    if args.vt:
        key = args.vt_key or os.environ.get("VT_API_KEY")
        if not key:
            print(f"\n{C.YEL}VT atlandi: VT_API_KEY tanimli degil.{C.RESET}", file=sys.stderr)
        else:
            vt_results = enrich_virustotal(findings, args.ip, args.hash, key)
            print_vt(vt_results)

    if args.check:
        run_check(findings)

    if args.json:
        payload = {
            "summary": {
                "events": len(events), "unparsed": bad,
                "findings": len(findings),
                "by_severity": dict(Counter(f.severity for f in findings)),
            },
            "findings": [f.to_dict() for f in
                         sorted(findings, key=lambda x: -SEV_RANK[x.severity])],
        }
        if vt_results:
            payload["virustotal"] = vt_results
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False)
        print(f"\n{C.GRN}JSON yazildi:{C.RESET} {args.json}")

    # cikis kodu: kritik/high bulgu varsa 1 (CI/otomasyon icin)
    return 1 if any(f.severity in ("critical", "high") for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
