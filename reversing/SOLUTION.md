# SOLUTION — eğitmen çözümü (SPOILER)

> Bu dosya tüm cevapları içerir. Öğrencilere challenge'ı vermeden önce silmek/gizlemek
> isteyebilirsin.

## Stage 0 — `stage0.ps1`
Base64 (UTF-16LE) blob'u çöz:
```bash
grep '^\$enc' stage0.ps1 | cut -d'"' -f2 | base64 -d | iconv -f UTF-16LE -t UTF-8
```
Çıktı aşama 1 görevini anlatır (binary'yi reverse et, parolayı bul).

## Stage 1 — parola
Parola `enc_pass[]` dizisinde **XOR 0x5A** ile saklı. `strings` boş döner.

- **radare2:** `aaa` → `pdf @ main`; `deobf()` içinde `xor al, 0x5a` döngüsü görünür.
  `enc_pass` baytları: `31 6e 2a 6b 29 2e 6a 34 6e`. Her baytı 0x5A ile XOR'la.
- **gdb:** `break strcmp` → `run x` → `x/s $rsi` (beklenen parola buffer'ı).
- **Elle:** `python3 -c "print(bytes(b^0x5A for b in [49,110,42,107,41,46,106,52,110]).decode())"`

**Parola:** `k4p1st0n4`

```
./stage1.elf k4p1st0n4
[+] Stage-1 GECILDI!
[+] Stage-2 anahtari: R3dPh4ntom
```
(Stage-2 anahtarı `enc_key2[]` içinde XOR 0x33 ile saklı → `R3dPh4ntom`.)

## Stage 2 — flag + anti-debug bypass
`cipher[]` = `FLAG ^ repeat("R3dPh4ntom")`. Doğru anahtarla XOR → flag.

**Anti-debug:** `being_debugged()` (Linux `ptrace(PTRACE_TRACEME)`, Windows
`IsDebuggerPresent`) debugger varsa `tamper=1` yapar; bu da anahtarın ilk baytını
bozar → flag yanlış çözülür. Yani düz `gdb ./stage2 ; run` **çalışmaz**.

Normal çalıştırmada (debugger yok) doğru anahtarla sorunsuz çözer:
```
./stage2.elf R3dPh4ntom
[+] Stage-2 GECILDI! Zincir tamam.
[+] FLAG{aybusec_z1nc1r_tamam_edr_2_flag}
```

**Debugger altında çözmek için** (bypass yollarından biri):
- gdb'de `ptrace` dönüşünü sıfırla: `break ptrace` → `run` → `finish` → `set $rax = 0`
  → `continue`. (veya `catch syscall ptrace` + return değerini 0 yap)
- ya da binary'de `being_debugged` çağrısını NOP'la / dönüşü 0'a patch'le (radare2 `w`).
- Windows'ta `IsDebuggerPresent` dönüşünü x64dbg ile 0 yap.

## Gömülü sırlar (referans)
| | değer |
|---|---|
| Stage-1 parola | `k4p1st0n4` (XOR 0x5A) |
| Stage-2 anahtar | `R3dPh4ntom` (XOR 0x33) |
| FLAG | `FLAG{aybusec_z1nc1r_tamam_edr_2_flag}` |
