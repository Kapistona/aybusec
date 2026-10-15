# aybusec — Log Analizi Eğitim Laboratuvarı

Saf Python (stdlib) ile yazılmış, **tek dosyalık bir SIEM log dedektif aracı** ve
içinde gerçek atak senaryoları gizli, **20K+ satırlık sentetik örnek log**. Kurulum
gerektirmez; amaç SOC / log analizi eğitiminde "samanlıkta iğne arama" pratiği yaptırmaktır.

> ⚠️ `siem_sample.log` tamamen **sentetiktir**. İçindeki tüm IP, kullanıcı, host, domain
> ve hash değerleri uydurmadır; gerçek bir sistem veya kişiye ait değildir. Yalnızca
> eğitim amaçlıdır.

## Hızlı başlangıç

```bash
git clone https://github.com/Kapistona/aybusec.git
cd aybusec
python3 analyze.py siem_sample.log
```

Python 3.8+ yeterli. Hiçbir `pip install` gerekmez.

## Örnek log hakkında

`siem_sample.log` tek dosyada **heterojen kaynakları** birleştirir (gerçek bir SIEM'in ham
hali gibi). Her satır: `timestamp host program: mesaj`.

| Kaynak | Program | İçerik |
|--------|---------|--------|
| Web | `nginx` | Erişim logları (içine SQLi/XSS/LFI/komut-enjeksiyonu gizli) |
| SSH | `sshd` | Başarılı/başarısız girişler, brute-force |
| Firewall | `kernel` | `[FW ALLOW/DROP]` — port tarama, exfil byte'ları |
| Windows | `Microsoft-Windows-Security-Auditing` | 4624/4625/4672/4688 |
| DNS | `named` | Normal sorgular + DNS tunnel |
| EDR | `edr` | Process telemetrisi: PowerShell, LOLBin, parent-child, hash |
| Host | `auditd`, `sudo` | Shell/komut izleri |

Atak/şüpheli satırlar toplamın **~%7'si**; gerisi normal gürültü. Zaman aralığı
12–14 Ekim 2026. Log tohumla (seed) üretildiği için tekrar üretilebilir.

## Araç ne yapıyor?

`read → parse → detector → report` katmanlı mimarisi. Her atak sınıfı için bir
**dedektör** çalışır, bulguları **MITRE ATT&CK**'e eşler ve bir **incident timeline**
(saldırı hikâyesi) kurar.

### Kullanım

```bash
python3 analyze.py siem_sample.log                 # tam rapor + bulgular + timeline
python3 analyze.py --list                          # dedektörleri listele
python3 analyze.py siem_sample.log --only edr_endpoint,ssh_bruteforce
python3 analyze.py siem_sample.log --exclude scanner_ua
python3 analyze.py siem_sample.log --check         # cevap anahtarı ile doğrula (PASS/FAIL)
python3 analyze.py siem_sample.log --json rapor.json
```

### VirusTotal zenginleştirme (tek tıkla IOC sorgusu)

Bulgulardaki IP'ler ve EDR hash'leri otomatik VirusTotal'de sorgulanır (saf `urllib`,
harici kütüphane yok):

```bash
export VT_API_KEY=xxxxxxxx          # ücretsiz VT API anahtarı
python3 analyze.py siem_sample.log --vt
python3 analyze.py --vt --ip 8.8.8.8 --hash <sha256>   # log olmadan tek atış sorgu
```

> Örnek log'daki IOC'ler sentetik olduğundan VT'de çoğu "kayıt yok" döner — bu normaldir,
> mekanizmayı öğretmek içindir. Gerçek analizde kendi IOC'nizi sorgulayın. Ücretsiz tier
> ~4 istek/dk olduğu için araç sorgular arasına bekleme koyar.

## Dedektörler → MITRE ATT&CK

| Dedektör | Yakaladığı | MITRE |
|----------|-----------|-------|
| `ssh_bruteforce` | SSH brute-force → başarılı giriş (compromise) | T1110 |
| `win_bruteforce` | Windows 4625 patlaması → 4624 → 4672 (priv-esc) | T1110 |
| `port_scan` | Tek kaynaktan çok sayıda farklı port (FW DROP) | T1046 |
| `web_attack` | SQLi / XSS / LFI / komut enjeksiyonu | T1190, T1083, T1059 |
| `scanner_ua` | sqlmap / Nikto / nmap vb. tarayıcı imzaları | T1595 |
| `dns_tunnel` | Tek domaine yüksek hacimli/uzun TXT sorguları | T1071.004 |
| `data_exfil` | Dışa büyük hacimli outbound | T1048 |
| `impossible_travel` | Aynı kullanıcı, kısa sürede farklı ülke | T1078 |
| `suspicious_process` | auditd/sudo: reverse shell, dropper, `/etc/shadow` | T1059 |
| `edr_endpoint` | PowerShell obfuscation, LOLBin, LSASS dump, persistence, şüpheli parent | T1027, T1003.001, T1218, T1566, T1505.003, T1547.001 |

## Alıştırma fikirleri

1. Önce aracı çalıştırmadan log'u kendin tara — kaç incident bulabiliyorsun?
2. `CONFIG` sözlüğündeki eşikleri değiştir; false-positive / false-negative dengesini gözle.
3. Yeni bir dedektör yaz: `@detector("adi")` ile işaretli bir fonksiyon ekle, Event
   listesini tara, `Finding` döndür. Otomatik rapora ve timeline'a girer.
4. `--check` ile kendi dedektörünün senaryoyu yakalayıp yakalamadığını doğrula.
5. EDR zincirini (FIN-PC03) adım adım incele: makro → indirme → LSASS → persistence.

## Dosyalar

- `analyze.py` — dedektif aracı (tek dosya, stdlib)
- `siem_sample.log` — sentetik örnek SIEM log'u (~20K satır)
- `gen_log.py` — örnek log'u üreten script (senaryoları/oranları değiştirmek için)
