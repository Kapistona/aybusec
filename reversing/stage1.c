/*
 * aybusec reversing lab — Stage 1
 * -------------------------------
 * Hikaye: EDR'nin yakaladigi "p.exe" dropper'inin zararsiz numunesi.
 * AG'A CIKMAZ, KALICILIK KURMAZ, DOSYA YAZMAZ. Sadece bir parola dogrular.
 *
 * Gorev: Dogru parolayi bul. 'strings' yetmez; parola XOR 0x5A ile gizli.
 * Dogru parolayla calistirinca Stage-2 anahtarini verir.
 *
 * Derleme:  cc -O0 -o stage1 stage1.c      (veya: make)
 */
#include <stdio.h>
#include <string.h>

/* obfuscate edilmis veriler — plaintext binary icinde yok */
static unsigned char enc_pass[] = {49,110,42,107,41,46,106,52,110};        /* XOR 0x5A */
static unsigned char enc_key2[] = {97,0,87,99,91,7,93,71,92,94};           /* XOR 0x33 */

static void deobf(const unsigned char *src, int n, unsigned char key, char *out)
{
    int i;
    for (i = 0; i < n; i++)
        out[i] = (char)(src[i] ^ key);
    out[n] = '\0';
}

int main(int argc, char **argv)
{
    char pass[32], key2[32];

    if (argc < 2) {
        printf("Kullanim: %s <parola>\n", argv[0]);
        return 1;
    }

    deobf(enc_pass, (int)sizeof(enc_pass), 0x5A, pass);

    if (strcmp(argv[1], pass) == 0) {
        deobf(enc_key2, (int)sizeof(enc_key2), 0x33, key2);
        printf("[+] Stage-1 GECILDI!\n");
        printf("[+] Stage-2 anahtari: %s\n", key2);
        printf("    Devam:  ./stage2 %s\n", key2);
        return 0;
    }

    printf("[-] Yanlis parola. Ipucu: deobf() fonksiyonuna ve enc_pass dizisine bak.\n");
    return 1;
}
