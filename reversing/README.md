# aybusec reversing lab

SIEM/EDR senaryosunun devamı: EDR'nin `FIN-PC03`'te yakaladığı **`p.exe` dropper'ının
zararsız numunesini** tersine mühendislikle çöz. Çok aşamalı bir zincir — her aşamanın
çıktısı bir sonrakinin anahtarı.

> ⚠️ **Güvenli / inert.** Bu binary'ler ağa çıkmaz, kalıcılık kurmaz, dosya silmez.
> Sadece bir parola doğrular ve gömülü bir flag'i çözer. Yine de alışkanlık olsun diye
> izole bir ortamda (VM) çalış.

## Zincir

```
stage0.ps1   →   stage1(.elf/.exe)   →   stage2(.elf/.exe)
(encoded PS)     (XOR-obfuscate parola)   (anti-debug + FLAG decrypt)
```

1. **Stage 0 — `stage0.ps1`:** Log'daki `powershell -enc` olayının aynısı. Base64/UTF-16LE
   çöz, görevi oku.
2. **Stage 1 — `stage1`:** Doğru parolayı bul. `strings` yetmez; parola XOR ile gizli.
   Doğru parola → Stage-2 anahtarını verir.
3. **Stage 2 — `stage2`:** Stage-1 anahtarıyla gömülü flag'i çöz. **Anti-debug var:**
   debugger altında anahtarı bilerek bozar → bypass etmen gerekir. Çözünce `FLAG{...}`.

## Araçlar

`gdb`, `radare2`/`rizin`, `Ghidra`, `objdump`, `strings`, `xxd`. (Windows PE için x64dbg.)

## Derleme

Binary'ler repoda hazır (`*.elf` = Linux x86-64, `*.exe` = Windows x64). Yeniden derlemek:

```bash
make            # native (ELF ya da Mach-O)
make elf        # Linux x86-64 ELF   (docker ile)
make pe         # Windows x64 PE     (docker + mingw ile)
```

## Reversing pipeline (statik triyaj)

Harici araç gerektirmeyen (saf Python) bir ön-analiz. Verilen ikilileri inceler ve
**iki rapor** üretir — biri teknik, biri yönetimsel:

```bash
python3 rev_pipeline.py stage1.elf stage2.elf stage1.exe stage2.exe
# -> rapor_teknik.md   (analist: hash, mimari, yetenekler, string'ler)
# -> rapor_yonetim.md  (yönetici: sade dilde risk ve tavsiye)
```

## Dosyalar

- `stage0.ps1` — encoded PowerShell (aşama 0)
- `stage1.c`, `stage2.c` — kaynak kod
- `stage1.elf`, `stage2.elf` — Linux x86-64 binary
- `stage1.exe`, `stage2.exe` — Windows x64 binary
- `Makefile` — derleme (native / elf / pe)
- `rev_pipeline.py` — statik triyaj + rapor üreteci
- `SOLUTION.md` — **eğitmen çözümü (spoiler!)** — öğrenciye vermeden önce silmek isteyebilirsin
