#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
aybusec reversing pipeline — basit statik ikili (binary) triyaji
================================================================
Harici arac YOK (radare2/Ghidra gerekmez), saf Python stdlib. Verilen
ELF/PE dosyalarini statik inceler ve IKI rapor uretir:

  1) rapor_teknik.md   — analist icin: hash, mimari, yetenekler, string'ler
  2) rapor_yonetim.md  — yonetici icin: sade dilde risk ve tavsiye

Kullanim:
    python3 rev_pipeline.py stage1.elf stage2.elf stage1.exe stage2.exe
    python3 rev_pipeline.py *.elf *.exe --out .
"""
import argparse
import hashlib
import os
import re
import sys

# --- imza tablosu: string gecisi -> yetenek ------------------------------
CAPS = [
    ("Anti-debug / anti-analiz",
     ["ptrace", "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess"]),
    ("Ag / network",
     ["socket", "connect", "WSAStartup", "InternetOpen", "URLDownloadToFile",
      "gethostbyname", "WinHttp", "recv", "/dev/tcp"]),
    ("Process olusturma / calistirma",
     ["execve", "system", "CreateProcess", "WinExec", "ShellExecute", "fork", "popen"]),
    ("Dosya yazma / silme",
     ["CreateFileA", "CreateFileW", "WriteFile", "fopen", "unlink", "remove", "DeleteFile"]),
    ("Kalicilik (persistence)",
     ["schtasks", "CurrentVersion\\Run", "RegSetValue", "RegCreateKey", "crontab"]),
    ("Komut yorumlayici",
     ["/bin/sh", "/bin/bash", "cmd.exe", "powershell"]),
]
# yetenek -> risk agirligi (basit)
WEIGHT = {
    "Anti-debug / anti-analiz": 2,
    "Ag / network": 3,
    "Process olusturma / calistirma": 3,
    "Dosya yazma / silme": 1,
    "Kalicilik (persistence)": 3,
    "Komut yorumlayici": 2,
}

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def detect_format(data):
    if data[:4] == b"\x7fELF":
        mach = int.from_bytes(data[18:20], "little")
        arch = {0x3e: "x86-64", 0xb7: "ARM64", 0x03: "x86", 0x28: "ARM"}.get(mach, f"0x{mach:x}")
        return "ELF (Linux)", arch
    if data[:2] == b"MZ":
        off = int.from_bytes(data[0x3c:0x40], "little")
        arch = "?"
        if data[off:off+4] == b"PE\x00\x00":
            mach = int.from_bytes(data[off+4:off+6], "little")
            arch = {0x8664: "x86-64", 0x14c: "x86", 0xaa64: "ARM64"}.get(mach, f"0x{mach:x}")
        return "PE (Windows)", arch
    return "bilinmiyor", "?"

STR_RE = re.compile(rb"[\x20-\x7e]{4,}")

def extract_strings(data, limit=4000):
    return [m.group().decode("latin-1") for m in STR_RE.finditer(data)][:limit]

def analyze(path):
    with open(path, "rb") as f:
        data = f.read()
    fmt, arch = detect_format(data)
    strings = extract_strings(data)
    sset = "\n".join(strings)
    caps = {}
    for cap, sigs in CAPS:
        hits = sorted({s for s in sigs if s in sset})
        if hits:
            caps[cap] = hits
    # ilginc string'ler (format/komut/anahtar ipucu)
    interesting = [s for s in strings
                   if re.search(r"FLAG\{|/dev/|\.dll|\.exe|http|/bin/|Kullanim|anahtar|parola", s, re.I)]
    risk = sum(WEIGHT[c] for c in caps)
    return {
        "path": path, "name": os.path.basename(path), "size": len(data),
        "sha256": sha256(path), "format": fmt, "arch": arch,
        "caps": caps, "interesting": interesting[:12], "risk": risk,
        "nstrings": len(strings),
    }

def risk_label(score):
    if score >= 8:  return "YUKSEK"
    if score >= 4:  return "ORTA"
    if score >= 1:  return "DUSUK"
    return "ONEMSIZ"

def advice(caps):
    if "Ag / network" in caps or "Kalicilik (persistence)" in caps:
        return "Izole ortamda incele; ag/kalicilik belirtisi var, canliya alma."
    if "Anti-debug / anti-analiz" in caps:
        return "Anti-analiz tekniği iceriyor; dinamik analizde debugger bypass gerekir."
    return "Belirgin zararli yetenek yok; yine de guvenilmeyen kaynaktan calistirma."

# --- rapor uretimi --------------------------------------------------------
def tech_report(results):
    L = ["# Teknik Analiz Raporu", "",
         f"Incelenen dosya sayisi: **{len(results)}** · arac: aybusec rev_pipeline (statik)", ""]
    for r in results:
        L += [f"## {r['name']}", "",
              f"- **Tur / mimari:** {r['format']} · {r['arch']}",
              f"- **Boyut:** {r['size']:,} byte · **String:** {r['nstrings']}",
              f"- **SHA256:** `{r['sha256']}`",
              f"- **Risk skoru:** {r['risk']} ({risk_label(r['risk'])})", ""]
        if r["caps"]:
            L.append("**Tespit edilen yetenekler:**")
            for cap, hits in r["caps"].items():
                L.append(f"- {cap} — `{'`, `'.join(hits)}`")
        else:
            L.append("**Tespit edilen yetenek:** yok (minimal/temiz)")
        L.append("")
        if r["interesting"]:
            L.append("**Dikkat ceken string'ler:**")
            L.append("```")
            L += r["interesting"]
            L.append("```")
        L += ["", f"**Degerlendirme:** {advice(r['caps'])}", "", "---", ""]
    return "\n".join(L)

def mgmt_report(results):
    worst = max((r["risk"] for r in results), default=0)
    overall = risk_label(worst)
    L = ["# Yonetim Ozeti — Dosya Analizi", "",
         f"**Genel durum: {overall} risk.** Toplam {len(results)} dosya incelendi. "
         "Rapor teknik olmayan okuyucu icin sadelestirilmistir.", "",
         "| Dosya | Tur | Risk | Ne yapmali |",
         "|-------|-----|------|------------|"]
    for r in results:
        L.append(f"| {r['name']} | {r['format'].split(' ')[0]} | **{risk_label(r['risk'])}** | {advice(r['caps'])} |")
    L += ["",
          "**Kisa aciklama:** Risk skoru, dosyanin tasidigi yeteneklere gore hesaplanir "
          "(ag erisimi, kalicilik, process calistirma vb. riski artirir). YUKSEK/ORTA "
          "dosyalar izole (sandbox) ortamda incelenmeli, canli sisteme alinmamalidir.", ""]
    return "\n".join(L)

def main():
    ap = argparse.ArgumentParser(description="aybusec reversing pipeline (statik triyaj)")
    ap.add_argument("files", nargs="+", help="ELF/PE dosyalari")
    ap.add_argument("--out", default=".", help="raporlarin yazilacagi dizin")
    args = ap.parse_args()

    results = []
    for p in args.files:
        if not os.path.isfile(p):
            print(f"[!] atlandi (yok): {p}", file=sys.stderr)
            continue
        results.append(analyze(p))
    if not results:
        print("Incelenecek dosya yok.", file=sys.stderr)
        return 2

    results.sort(key=lambda r: -r["risk"])
    tpath = os.path.join(args.out, "rapor_teknik.md")
    mpath = os.path.join(args.out, "rapor_yonetim.md")
    with open(tpath, "w", encoding="utf-8") as f:
        f.write(tech_report(results))
    with open(mpath, "w", encoding="utf-8") as f:
        f.write(mgmt_report(results))

    print(f"[+] {len(results)} dosya incelendi.")
    for r in results:
        print(f"    {r['name']:<14} {r['format'].split(' ')[0]:<4} risk={r['risk']:<2} ({risk_label(r['risk'])})")
    print(f"[+] Teknik rapor : {tpath}")
    print(f"[+] Yonetim rapor: {mpath}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
