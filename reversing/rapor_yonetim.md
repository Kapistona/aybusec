# Yonetim Ozeti — Dosya Analizi

**Genel durum: ORTA risk.** Toplam 4 dosya incelendi. Rapor teknik olmayan okuyucu icin sadelestirilmistir.

| Dosya | Tur | Risk | Ne yapmali |
|-------|-----|------|------------|
| stage2.exe | PE | **ORTA** | Anti-analiz tekniği iceriyor; dinamik analizde debugger bypass gerekir. |
| stage1.exe | PE | **ORTA** | Belirgin zararli yetenek yok; yine de guvenilmeyen kaynaktan calistirma. |
| stage2.elf | ELF | **DUSUK** | Anti-analiz tekniği iceriyor; dinamik analizde debugger bypass gerekir. |
| stage1.elf | ELF | **ONEMSIZ** | Belirgin zararli yetenek yok; yine de guvenilmeyen kaynaktan calistirma. |

**Kisa aciklama:** Risk skoru, dosyanin tasidigi yeteneklere gore hesaplanir (ag erisimi, kalicilik, process calistirma vb. riski artirir). YUKSEK/ORTA dosyalar izole (sandbox) ortamda incelenmeli, canli sisteme alinmamalidir.
