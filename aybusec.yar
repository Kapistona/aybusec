/* aybusec — otomatik uretilmis YARA kurallari
   kaynak: analiz edilen bulgular · sentetik/egitim · ileride CrowdStrike IOA/IOC API'ye beslenebilir */

rule aybusec_webshell_indicators
{
    meta:
        author      = "aybusec"
        description = "Webshell / komut enjeksiyonu govde imzalari"
        mitre       = "T1505.003, T1059"
        severity    = "high"
    strings:
        $c1 = "cmd.exe /c"  ascii nocase
        $c2 = "/bin/sh"     ascii
        $p1 = "eval("       ascii nocase
        $p2 = "system("     ascii nocase
        $p3 = "passthru("   ascii nocase
        $p4 = "shell_exec(" ascii nocase
        $w  = "whoami"      ascii nocase
    condition:
        2 of them
}

rule aybusec_reverse_shell_dropper
{
    meta:
        author      = "aybusec"
        description = "Linux reverse shell / dropper komut imzalari"
        mitre       = "T1059"
        severity    = "critical"
    strings:
        $devtcp = "/dev/tcp/" ascii
        $nc_e   = "nc -e"     ascii
        $bash_i = "bash -i"   ascii
        $pty    = "pty.spawn" ascii
        $shadow = "/etc/shadow" ascii
        $wget_ip = /wget\s+https?:\/\/\d{1,3}(\.\d{1,3}){3}/ ascii
    condition:
        any of them
}

rule aybusec_edr_powershell_dropper_chain
{
    meta:
        author      = "aybusec"
        description = "Encoded PowerShell dropper + LOLBin indirme + LSASS cred-dump zinciri"
        mitre       = "T1059.001, T1027, T1105, T1218, T1003.001"
        severity    = "high"
        reference   = "github.com/Kapistona/aybusec"
    strings:
        $ps_enc    = "-enc"          ascii wide nocase
        $ps_hidden = "-w hidden"     ascii wide nocase
        $ps_iex    = "IEX"           ascii wide
        $ps_dl     = "DownloadString" ascii wide nocase
        $amsi      = "AmsiUtils"     ascii wide nocase
        $lsass1    = "comsvcs.dll"   ascii wide nocase
        $lsass2    = "MiniDump"      ascii wide nocase
        $mimi      = "sekurlsa::logonpasswords" ascii wide nocase
        $lol_ct    = "certutil"      ascii wide nocase
        $lol_uc    = "-urlcache"     ascii wide nocase
        $lol_bits  = "bitsadmin /transfer" ascii wide nocase
    condition:
        2 of them
}
