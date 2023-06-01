#include <stdio.h>
#include <stdlib.h>
#include <openssl/des.h>
#include <openssl/rsa.h>
#include <openssl/md5.h>
#include <openssl/pem.h>
#include <getopt.h>

#define DES_KEY		"88T3j05dtFu8="
#define RSA_KEY      "-----BEGIN RSA PUBLIC KEY-----\n\
MIGJAoGBAK7cBjOnooyuBwJqTfXqcHnIPvxDPbm6IsEc wtDlwKDukESn5X+v8Bre\n\
xK3zylUPu1kAIFY53x+BQjnBgatYIXsffgjmm9uHqIrJlc9v8Vh4RXgCITcc4ZvB\n\
NBmreHQqVO FVbF5Z5XHVgTE/8dfXRqmzuuKub9MksTpfBb8bqEhbAgMBAAE=\n\
-----END RSA PUBLIC KEY-----"


#define BDINFO_LEN  0xde96
#define BDINFO_DATA_LEN 0xdd80
#define BDINFO_DEC_LEN  0xdd7c
#define BDINFO_RSA_OFFSET   0xdd80
#define BDINFO_RSA_LEN      0x80

#define BDINFO_END_MAGIC    "BDINFO_END"

#define BDINFO_KEY_VALUE_SEPARATOR  " = "
#define BDINFO_VAL_NUM_VALS         64

struct bdinfo_value {
    char *line_ptr;
    char *key;
    char *value;
};

struct bdinfo_args {
    const char *input_file;
    const char *output_file;
    const char *key;
    int skip_rsa;
};

struct bdinfo_value bdinfo_values[BDINFO_VAL_NUM_VALS];

int validate_bdinfo_md5(unsigned char *input, size_t length) {
    unsigned char md5_output[MD5_DIGEST_LENGTH];
    unsigned char rsa_md5[BDINFO_RSA_LEN];
    RSA *rsa = NULL;
    BIO *bp = NULL;
    int ret = 0;
    int sz;

    bp = BIO_new_mem_buf(RSA_KEY, strlen(RSA_KEY));
    if (!bp) {
        fprintf(stderr, "Error allocating RSA public key\n");
        ret = 1;
        goto out;
    }

    rsa = PEM_read_bio_RSAPublicKey(bp, NULL, NULL, NULL);
    if (!rsa) {
        fprintf(stderr, "Error reading RSA public key\n");
        ret = 1;
        goto out;
    }

    sz = RSA_public_decrypt(BDINFO_RSA_LEN, &input[BDINFO_RSA_OFFSET], rsa_md5, rsa, 1);
    if (sz < 10) {
        fprintf(stderr, "Error decrypting RSA digest\n");
        ret = 1;
        goto out;
    }

    MD5(input, BDINFO_DATA_LEN, md5_output);
    if (memcmp(rsa_md5, md5_output, MD5_DIGEST_LENGTH) != 0) {
        fprintf(stderr, "Error validating MD5\n");
        ret = 1;
        goto out;
    }

out:
    if (rsa) {
        RSA_free(rsa);
    }
    if (bp) {
        BIO_free(bp);
    }
    return ret;
}

int decrypt(char *input, char *output, size_t length) {
    DES_cblock deskey = {};
    DES_cblock ivec = {};
    DES_key_schedule dschedule = {};

    DES_string_to_key(DES_KEY, &deskey);
    if (DES_set_key_checked(&deskey, &dschedule)) {
        fprintf(stderr,"Error setting key\n");
        return 1;
    }
    DES_ncbc_encrypt(input, output, length, &dschedule, &ivec, 0);

    return 0;
}

int print_bdinfo(const char *key) {
    struct bdinfo_value *bdval;
    int ret = 0;
    int i;

    if (key) {
        ret = 1;
    }

    for (i = 0; i < BDINFO_VAL_NUM_VALS && (bdval = &bdinfo_values[i])->line_ptr; i++) {
        if (key) {
            if (strcmp(bdval->key, key) != 0) {
                continue;
            }

            printf("%s\n", bdval->value);
            return 0;
        } else {
            printf("%s = %s\n", bdval->key, bdval->value);
        }
    }

    if (ret && key) {
        fprintf(stderr, "Key %s not found in bdinfo\n", key);
    }

    return ret;
}

int parse_bdinfo(char *buf, size_t buf_len) {
    struct bdinfo_value *bdval;
    char *kv_pair, *ptr, *eof_marker;
    int i;

    ptr = buf;
    memset(bdinfo_values, 0, sizeof(bdinfo_values));

    /*Check for null-terminated BDINFO_END marker */
    eof_marker = strstr(ptr, BDINFO_END_MAGIC);
    if (!eof_marker) {
        fprintf(stderr, "EOF Marker not found\n");
        return 1;
    }
    if (eof_marker + (strlen(BDINFO_END_MAGIC)) > buf + buf_len || (eof_marker != buf && *(eof_marker - 1) != '\n')) {
        fprintf(stderr, "Invalid EOF Marker\n");
        return 1;
    }

    /* Separate BDINFO lines */
    for (i = 0; (kv_pair = strsep(&ptr, "\n")) && i < BDINFO_VAL_NUM_VALS; i++){
        if (!strncmp(kv_pair, BDINFO_END_MAGIC, strlen(BDINFO_END_MAGIC))) {
            break;
        }

        bdinfo_values[i].line_ptr = kv_pair;
    }

    /* Parse lines */
    for (i = 0; i < BDINFO_VAL_NUM_VALS && (bdval = &bdinfo_values[i])->line_ptr; i++) {
        ptr = strstr(bdval->line_ptr,BDINFO_KEY_VALUE_SEPARATOR);
        if (!ptr) {
            /* ToDo: Invalid line */
            return 1;
        }
        bdval->key = bdval->line_ptr;
        bdval->value = ptr + strlen(BDINFO_KEY_VALUE_SEPARATOR);

        memset(ptr, 0, strlen(BDINFO_KEY_VALUE_SEPARATOR) * sizeof(char));
    }

    /* ToDo: Validate for unique keys */
    return 0;
}

int write_output(const char *output_file, char *data, size_t len) {
    FILE *bdinfo_output;
    int ret = 0;

    bdinfo_output = fopen(output_file, "wb");
    if (!bdinfo_output) {
        fprintf(stderr, "Error opening output file!\n");
        ret = 1;
        goto out;
    }

    fwrite(data, sizeof(char), len, bdinfo_output);

out:
    if (bdinfo_output)
        fclose(bdinfo_output);

    return ret;
}

int main(int argc, char *argv[]) {
    static struct bdinfo_args bdargs;
    char bdinfo_encrypted[BDINFO_LEN] = {};
    char bdinfo_decrypted[BDINFO_LEN] = {};
    size_t read_bytes;
    FILE *bdinfo_input;
    int ret = 0;
    int c;

    memset(&bdargs, 0, sizeof(bdargs));

    while ((c = getopt(argc, argv, "hi:o:k:r")) != -1) {
        switch (c) {
            case 'h':
                return 0;
            case 'i':
                bdargs.input_file = optarg;
                break;
            case 'k':
                bdargs.key = optarg;
                break;
            case 'o':
                bdargs.output_file = optarg;
                break;
            case 'r':
                bdargs.skip_rsa = 1;
                break;
            default:
                return 1;
        }
    }

    /* Validate CLI arguments */
    if (!bdargs.input_file) {
        fprintf(stderr, "Input file required.\n");
    } else if (bdargs.output_file && bdargs.key) {
        fprintf(stderr, "Decryption and dump not possible.\n");
    }

    bdinfo_input = fopen(bdargs.input_file, "rb");
    if (!bdinfo_input) {
        fprintf(stderr, "Error opening file\n");
        ret = 1;
        goto out;
    }

    read_bytes = fread(bdinfo_encrypted, sizeof(char), BDINFO_LEN, bdinfo_input);
    if (read_bytes != BDINFO_LEN) {
        fprintf(stderr, "Read bytes does not equal expected value\n");
        ret = 1;
        goto out;
    }

    if (!bdargs.skip_rsa) {
        ret = validate_bdinfo_md5(bdinfo_encrypted, BDINFO_LEN);
        if (ret) {
            fprintf(stderr, "Error checking RSA signature\n");
            ret = 1;
            goto out;
        }
    }

    ret = decrypt(bdinfo_encrypted + 4, bdinfo_decrypted, BDINFO_DEC_LEN);
    if (ret) {
        fprintf(stderr, "Error decrypting bdinfo\n");
        goto out;
    }

    if (bdargs.output_file) {
        ret = write_output(bdargs.output_file, bdinfo_decrypted, BDINFO_LEN);
        if (ret) {
            fprintf(stderr, "Error writing output file\n");
            goto out;
        }
    } else {
        ret = parse_bdinfo(bdinfo_decrypted, BDINFO_LEN);
        if (ret) {
            fprintf(stderr, "Error parsing bdinfo\n");
            goto out;
        }

        ret = print_bdinfo(bdargs.key);
    }

out:
    if (bdinfo_input)
        fclose(bdinfo_input);
    return ret;
}