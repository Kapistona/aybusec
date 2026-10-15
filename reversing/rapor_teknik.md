# Teknik Analiz Raporu

Incelenen dosya sayisi: **4** · arac: aybusec rev_pipeline (statik)

## stage2.exe

- **Tur / mimari:** PE (Windows) · x86-64
- **Boyut:** 246,849 byte · **String:** 4000
- **SHA256:** `a4170922dd856cf58712bc23588491df5d753c3f67c5f142ba4d09909332e844`
- **Risk skoru:** 6 (ORTA)

**Tespit edilen yetenekler:**
- Anti-debug / anti-analiz — `IsDebuggerPresent`
- Process olusturma / calistirma — `system`
- Dosya yazma / silme — `remove`

**Dikkat ceken string'ler:**
```
Kullanim: %s <stage2-anahtari>
[-] Bos anahtar.
FLAG{
[-] Yanlis anahtar (ya da debugger takili?). Tekrar dene.
KERNEL32.dll
msvcrt.dll
```

**Degerlendirme:** Anti-analiz tekniği iceriyor; dinamik analizde debugger bypass gerekir.

---

## stage1.exe

- **Tur / mimari:** PE (Windows) · x86-64
- **Boyut:** 246,823 byte · **String:** 4000
- **SHA256:** `82c4831cf1819a401a35c254aba2b59bf0e64d5aa51b5c39cf851d745d091cad`
- **Risk skoru:** 4 (ORTA)

**Tespit edilen yetenekler:**
- Process olusturma / calistirma — `system`
- Dosya yazma / silme — `remove`

**Dikkat ceken string'ler:**
```
Kullanim: %s <parola>
[+] Stage-2 anahtari: %s
[-] Yanlis parola. Ipucu: deobf() fonksiyonuna ve enc_pass dizisine bak.
KERNEL32.dll
msvcrt.dll
```

**Degerlendirme:** Belirgin zararli yetenek yok; yine de guvenilmeyen kaynaktan calistirma.

---

## stage2.elf

- **Tur / mimari:** ELF (Linux) · x86-64
- **Boyut:** 19,168 byte · **String:** 160
- **SHA256:** `38525518b3ac43c6b422bceb1a640230a03e036ade973eed42248a85ace1853b`
- **Risk skoru:** 2 (DUSUK)

**Tespit edilen yetenekler:**
- Anti-debug / anti-analiz — `ptrace`

**Dikkat ceken string'ler:**
```
Kullanim: %s <stage2-anahtari>
[-] Bos anahtar.
FLAG{
[-] Yanlis anahtar (ya da debugger takili?). Tekrar dene.
```

**Degerlendirme:** Anti-analiz tekniği iceriyor; dinamik analizde debugger bypass gerekir.

---

## stage1.elf

- **Tur / mimari:** ELF (Linux) · x86-64
- **Boyut:** 17,640 byte · **String:** 104
- **SHA256:** `881f4cd62841657fd4761d5391c1be296fe7d713984295a9be3229905dd9b557`
- **Risk skoru:** 0 (ONEMSIZ)

**Tespit edilen yetenek:** yok (minimal/temiz)

**Dikkat ceken string'ler:**
```
Kullanim: %s <parola>
[+] Stage-2 anahtari: %s
[-] Yanlis parola. Ipucu: deobf() fonksiyonuna ve enc_pass dizisine bak.
```

**Degerlendirme:** Belirgin zararli yetenek yok; yine de guvenilmeyen kaynaktan calistirma.

---
