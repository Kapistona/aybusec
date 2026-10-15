/*
 * aybusec reversing lab — Stage 2  (FINAL)
 * ----------------------------------------
 * Girdi: Stage-1'in verdigi anahtar.
 * Bu anahtar, gomulu sifreli metni (FLAG) cozen XOR anahtaridir.
 * Yanlis anahtar -> coptur cikti; dogru anahtar -> FLAG{...}.
 *
 * EK ZORLUK (anti-debug): Program bir debugger altinda calisiyorsa (ptrace),
 * anahtari bilerek bozar ve bayragi YANLIS cozer. Yani sadece gdb'de
 * "run" demek yetmez — ptrace kontrolunu atlatman (patch/bypass) gerekir.
 *
 * Derleme:  cc -O0 -o stage2 stage2.c      (veya: make)
 */
#include <stdio.h>
#include <string.h>

/* platforma gore anti-debug */
#if defined(__linux__)
#include <sys/ptrace.h>
static int being_debugged(void) { return ptrace(PTRACE_TRACEME, 0, 0, 0) < 0; }
#elif defined(_WIN32)
#include <windows.h>
static int being_debugged(void) { return IsDebuggerPresent() ? 1 : 0; }
#else
static int being_debugged(void) { return 0; }
#endif

/* FLAG ^ repeat(KEY2) — plaintext binary icinde yok */
static unsigned char cipher[] = {
    20,127,37,23,19,85,23,22,26,30,55,80,59,42,89,90,13,69,
    29,50,38,82,9,49,5,107,11,16,29,50,96,108,2,60,9,83,19
};

int main(int argc, char **argv)
{
    char out[64];
    unsigned char tamper;
    int i, n, klen;
    char *key;

    if (argc < 2) {
        printf("Kullanim: %s <stage2-anahtari>\n", argv[0]);
        return 1;
    }

    /* anti-debug: debugger altindaysak anahtari boz */
    tamper = being_debugged() ? 0x01 : 0x00;

    key = argv[1];
    klen = (int)strlen(key);
    if (klen == 0) {
        printf("[-] Bos anahtar.\n");
        return 1;
    }

    n = (int)sizeof(cipher);
    if (n > 63) n = 63;
    for (i = 0; i < n; i++) {
        unsigned char k = (unsigned char)key[i % klen] ^ (i == 0 ? tamper : 0);
        out[i] = (char)(cipher[i] ^ k);
    }
    out[n] = '\0';

    if (strncmp(out, "FLAG{", 5) == 0) {
        printf("[+] Stage-2 GECILDI! Zincir tamam.\n");
        printf("[+] %s\n", out);
        return 0;
    }

    printf("[-] Yanlis anahtar (ya da debugger takili?). Tekrar dene.\n");
    return 1;
}
