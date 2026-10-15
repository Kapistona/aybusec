# aybusec reversing lab — Stage 0
# SIEM/EDR logundaki "powershell -enc <base64>" olayinin birebir ayni mantigi.
# Bu blob, -EncodedCommand gibi UTF-16LE + Base64 kodlanmistir. Coz ve talimati oku.
#
# Linux/mac (pwsh) veya Windows PowerShell'de:
#   $b = Get-Content stage0.ps1 | Select-String '^\$enc' ; # ya da asagidaki $enc'i al
#   [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($enc))
#
# PowerShell yoksa saf bash ile:
#   grep '^\$enc' stage0.ps1 | cut -d'"' -f2 | base64 -d | iconv -f UTF-16LE -t UTF-8

$enc = "YQB5AGIAdQBzAGUAYwAgAHIAZQB2AGUAcgBzAGkAbgBnACAAegBpAG4AYwBpAHIAaQAgAC0AIABBAHMAYQBtAGEAIAAxAAoASABlAGQAZQBmADoAIAAuAC8AcwB0AGEAZwBlADEAIABiAGkAbgBhAHIAeQAnAHMAaQBuAGkAIAB0AGUAcgBzAGkAbgBlACAAbQB1AGgAZQBuAGQAaQBzAGwAaQBrAGwAZQAgAGMAbwB6ACAAdgBlACAAZABvAGcAcgB1ACAAcABhAHIAbwBsAGEAeQBpACAAYgB1AGwALgAKAEkAcAB1AGMAdQA6ACAAJwBzAHQAcgBpAG4AZwBzACcAIAB5AGUAdABtAGUAegA7ACAAcABhAHIAbwBsAGEAIABYAE8AUgAgAGkAbABlACAAbwBiAGYAdQBzAGMAYQB0AGUAIABlAGQAaQBsAG0AaQBzAC4AIAByAGEAZABhAHIAZQAyAC8AZwBkAGIALwBHAGgAaQBkAHIAYQAgAGsAdQBsAGwAYQBuAC4ACgBCAHUAbAB1AG4AYwBhADoAIAAuAC8AcwB0AGEAZwBlADEAIAA8AHAAYQByAG8AbABhAD4AIAAgAC0APgAgACAAcwBhAG4AYQAgAFMAdABhAGcAZQAtADIAIABhAG4AYQBoAHQAYQByAGkAbgBpACAAdgBlAHIAaQByAC4A"

[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($enc))
