#include <stdio.h>
#include <stdlib.h>
#include <openssl/des.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define DES_KEY		"88T3j05dtFu8="
#define BDINFO_LEN  0xde96
#define BDINFO_DEC_LEN  0xdd7c

int decrypt(unsigned char *input, unsigned char *output, size_t length) {
    DES_cblock deskey = {};
    DES_cblock ivec = {};
    DES_key_schedule dschedule = {};
    int ret;

    DES_string_to_key(DES_KEY, &deskey);
    if (DES_set_key_checked(&deskey, &dschedule)) {
        printf("Error setting key\n");
        return 1;
    }
    DES_ncbc_encrypt(input, output, length, &dschedule, &ivec, 0);

    return 0;
}

int write_output(const char *output_file, char *data, size_t len) {
    FILE *bdinfo_output;
    int ret = 0;

    bdinfo_output = fopen(output_file, "wb");
    if (!bdinfo_output) {
        printf("Error opening output file!\n");
        ret = 1;
        goto out;
    }

    fwrite(data, sizeof(unsigned char), len, bdinfo_output);

out:
    if (bdinfo_output)
        fclose(bdinfo_output);

    return ret;
}

int main(int argc, char *argv[]) {
    unsigned char bdinfo_encrypted[BDINFO_LEN] = {};
    unsigned char bdinfo_decrypted[BDINFO_LEN] = {};
    const char *input_file;
    const char *output_file;
    size_t read_bytes;
    FILE *bdinfo_input;
    int ret = 0;

    if (argc != 3) {
        printf("Usage: %s <input> <output>\n", argv[0]);
        return 1;
    }

    input_file = argv[1];
    output_file = argv[2];

    bdinfo_input = fopen(input_file, "rb");
    if (!bdinfo_input) {
        printf("Error opening file\n");
        ret = 1;
        goto out;
    }

    read_bytes = fread(bdinfo_encrypted, sizeof(unsigned char), BDINFO_LEN, bdinfo_input);
    if (read_bytes != BDINFO_LEN) {
        printf("Read bytes does not equal expected value\n");
        ret = 1;
        goto out;
    }

    ret = decrypt(bdinfo_encrypted + 4, bdinfo_decrypted, BDINFO_DEC_LEN);
    if (ret) {
        goto out;
    }
    write_output(output_file, bdinfo_decrypted, BDINFO_LEN);

out:
    fclose(bdinfo_input);
    return ret;
}