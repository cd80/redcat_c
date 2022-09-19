#include <stdio.h>
#include <stdlib.h> // malloc
#include <string.h> // strcpy
#include <unistd.h>
#include <getopt.h>
#include <dirent.h>
#include <pthread.h>
#include <sys/stat.h> // stat
#include <sys/types.h> // stat
#include <openssl/evp.h>
#include <openssl/types.h>

void help();
char is_regular_file(const char *path);
void process_file(char *input, char *output);
void process_directory(char *input, char *output);
void thread_handler(void *);
void do_aes(FILE *fp_in, FILE *fp_out, const EVP_CIPHER *cipher,
            const unsigned char *key, const unsigned char *iv, int enc);
void do_digest(FILE *fp_in, FILE *fp_out, const EVP_MD *digest);

char *g_algorithm = NULL;
char g_verbose = 0;
int g_do_decrypt = 0;

int main(int argc, char *argv[]) {
    int c;
    char *input = NULL, *output = NULL;

    while ((c = getopt(argc, argv, "i:o:a:dv")) != -1) {
        switch (c) {
            case 'i':
                input = malloc(strlen(optarg) + 1);
                strcpy(input, optarg);
                break;
            case 'o':
                output = malloc(strlen(optarg) + 1);
                strcpy(output, optarg);
                break;
            case 'a':
                g_algorithm = malloc(strlen(optarg) + 1);
                strcpy(g_algorithm, optarg);
                break;
            case 'd':
                g_do_decrypt = 1;
                break;
            case 'v':
                g_verbose = 1;
                break;
            default:
                break;
        }
    }

    // check options

    if (input == NULL || g_algorithm == NULL) {
        help();
        exit(1);
    }

    OpenSSL_add_all_algorithms(); // for EVP_get_cipherbyname(), EVP_get_digestbyname()

    // process input
    // check if input is directory / file
    if (is_regular_file(input)) {
        process_file(input, output);
    }
    else {
        if (output == NULL) {
            output = "out";
        }
        process_directory(input, output);
    }

    return 0;
}

void help() {
  struct command_usage {
    const char *option;
    const char *usage;
  } usage[] = {
    {"-h", "Print this message"},
    {"-i <file/directory>", "Input file/directory"},
    {"-o <file/directory>", "Output file/directory"},
    {"-a <algorithm>", "Algorithm to use. ex) aes{128,192,256}{cbc,ecb}, md5, sha{1, 256, 512}, default md5"},
    {"-d", "Decrypt"},
    {"-v", "Verbose"},
  };

  fprintf(stderr, "usage: crypt -i <input> -o <output> -a <algorithm> [OPTIONS]\n");
  for (int i=0; i<sizeof(usage)/sizeof(struct command_usage); ++i) {
    fprintf(stderr, "    %-16s\t| %s\n", usage[i].option, usage[i].usage);
  }
}

char is_regular_file(const char *path)
{
    struct stat path_stat;
    stat(path, &path_stat);
    return !!(S_ISREG(path_stat.st_mode));
}

unsigned int get_file_size(const char *path) {
    struct stat st;
    stat(path, &st);
    return st.st_size;
}

char create_directory(const char *path) {
    // check if directory exists
    struct stat st;
    if (stat(path, &st) == -1) {
        return !(mkdir(path, 0755));
    }

    return !(is_regular_file(path));
}

void process_file(char *input, char *output) {
    char *buf_in = NULL, *buf_out = NULL;
    FILE *fp_in = NULL;
    FILE *fp_out = NULL;
    unsigned int file_size = 0;

    if (g_verbose) {
        printf("processing: %s\n", input);
    }

    // open input file
    fp_in = fopen(input, "rb");
    if (fp_in == 0) {
        fprintf(stderr, "[Error] Couldn't open input file %s for reading\n", input);
        exit(1);
    }

    // open output file
    fp_out = fopen(output, "wb");
    if (fp_out == 0) {
        fp_out = stdout;
    }

    if (memcmp(g_algorithm, "aes", 3) == 0) {
        // aes128cbc, aes192cbc, aes256cbc
        // aes128ecb, aes192ecb, aes256ecb
        char bit[4] = {0, };
        char mode[4] = {0, };
        char evp_alg_string[12] = {0, };
        unsigned char key[33] = {0, };
        unsigned char iv[33] = {0, };
        const EVP_CIPHER *cipher = EVP_enc_null();

        memset(key, 0x41, 32);
        memset(iv, 0x61, 32);
        if (strlen(g_algorithm) == 9) {
            memcpy(bit, &g_algorithm[3], 3);
            memcpy(mode, &g_algorithm[6], 3);
        }
        else {
            fprintf(stderr, "[Warning] aes should be specified as [aes128cbc, etc.]. defaulting to aes128cbc\n");
            g_algorithm = "aes128cbc";
            memcpy(bit, "128", 3);
            memcpy(mode, "cbc", 3);
        }

        sprintf(evp_alg_string, "aes-%s-%s", bit, mode);
        cipher = EVP_get_cipherbyname(evp_alg_string);
        if (cipher == NULL) {
            fprintf(stderr, "[Warning] failed to get algorithm [%s], defaulting to aes128cbc\n", g_algorithm);
            cipher = EVP_get_cipherbyname("aes-128-cbc");
            if (cipher == NULL) {
                fprintf(stderr, "[Error] couldn't get aes-128-cbc\n");
                exit(1);
            }
        }

        do_aes(fp_in, fp_out, cipher, key, iv, !(g_do_decrypt));
    }
    
    else {
        // md5, sha1, sha256, sha512
        const EVP_MD *digest = EVP_md_null();
        digest = EVP_get_digestbyname(g_algorithm);

        if (digest == NULL) {
            fprintf(stderr, "[Warning] failed to get algorithm [%s], defaulting to md5\n", g_algorithm);
            digest = EVP_get_digestbyname("md5");
            if (digest == NULL) {
                fprintf(stderr, "[Error] couldn't get md5\n");
                exit(1);
            }
        }

        do_digest(fp_in, fp_out, digest);
    }
}


void process_directory(char *input, char *output) {
    char *path_in, *path_out;
    DIR *directory;
    struct dirent *ent;
    
    if (strcmp(input, output) == 0) {
        if (memcmp(g_algorithm, "aes", 3) == 0) {
            fprintf(stderr, "[Warning] input directory == output directory.");
        }
        else {
            fprintf(stderr, "[Error] Cannot set input == output when using hash function");
            exit(1);
        }
    }
    if (!create_directory(output)) {
        fprintf(stderr, "[Error] Failed to create output directory %s\n", output);
        exit(1);
    }

    directory = opendir(input);
    if (directory == NULL) {
        fprintf(stderr, "[Error] Failed to open directory %s\n", output);
        exit(1);
    }
    
    do {
        ent = readdir(directory);
        if (ent == NULL) break;
        if (strcmp(ent->d_name, ".") == 0 ||
            strcmp(ent->d_name, "..") == 0)
            continue;

        path_in = malloc(strlen(input) + strlen(ent->d_name) + 2);
        path_out = malloc(strlen(output) + strlen(ent->d_name) + 2);
        sprintf(path_in, "%s/%s", input, ent->d_name);
        sprintf(path_out, "%s/%s", output, ent->d_name);

        process_file(path_in, path_out);

        free(path_in);
        free(path_out);
    } while(ent != NULL);
}


// https://zerous0.tistory.com/9
void do_aes(FILE *fp_in, FILE *fp_out, const EVP_CIPHER *cipher,
            const unsigned char *key, const unsigned char *iv, int enc) {
    int inlen, outlen;
    unsigned char inbuf[128], outbuf[128+EVP_MAX_BLOCK_LENGTH];
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    EVP_CIPHER_CTX_init(ctx);

    EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, enc);
    while ((inlen = fread(inbuf, 1, sizeof(inbuf), fp_in)) > 0) {
        EVP_CipherUpdate(ctx, outbuf, &outlen, inbuf, inlen);
        fwrite(outbuf, 1, outlen, fp_out);
    }

    EVP_CipherFinal_ex(ctx, outbuf, &outlen);
    fwrite(outbuf, 1, outlen, fp_out);

    EVP_CIPHER_CTX_cleanup(ctx);
}

void do_digest(FILE *fp_in, FILE *fp_out, const EVP_MD *digest) {
    int inlen, outlen;
    char outhex[129] = {0, };
    unsigned int digest_len;
    unsigned char inbuf[128], outbuf[64];
    EVP_MD_CTX *ctx;
    ctx = EVP_MD_CTX_new();

    EVP_DigestInit_ex(ctx, digest, NULL);
    while ((inlen = fread(inbuf, 1, sizeof(inbuf), fp_in)) > 0) {
        EVP_DigestUpdate(ctx, inbuf, inlen);
    }
    EVP_DigestFinal_ex(ctx, outbuf, &digest_len);

    for (int i = 0; i < digest_len; ++i) {
        sprintf(&outhex[i * 2], "%02x", outbuf[i]);
    }

    fwrite(outhex, 1, strlen(outhex), fp_out);
    fwrite("\n", 1, 1, fp_out);

    EVP_MD_CTX_free(ctx);
}
