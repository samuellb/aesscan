/*

  aesscan.c -- Utility to scan for AES keys in binaries

  Copyright © 2014 Samuel Lidén Borell <samuel@kodafritt.se>

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <nettle/aes.h>
#include <nettle/cbc.h>

#define READSIZE 1024

struct fileentry {
    char *name;
    long datalen;
    unsigned char *data;
};

enum ciphermode {
    AES128_CBC = 0,
    AES128_ECB,
    AES256_CBC,
    AES256_ECB
};

static const char ciphermodes[][11] = {
    "AES128_CBC",
    "AES128_ECB",
    "AES256_CBC",
    "AES256_ECB"
};


static const int cipher_iv_size[] = {
    AES_BLOCK_SIZE,
    0,
    AES_BLOCK_SIZE,
    0
};

static const size_t cipher_key_size[] = {
    128/8, /* TODO upgrade libnettle and use AES128_KEY_SIZE */
    128/8,
    256/8,
    256/8
};

enum padding {
    PKCS7,
    THROW_AWAY, /* throw away last block */
    NO_PADDING
};

static const char paddings[][11] = {
    "PKCS#7",
    "THROW_AWAY",
    "NONE"
};


static long offset;
static long maxlength;
static long numfiles;
static struct fileentry *files;
static char *scanfilename;
static FILE *scanfile;
static unsigned char *decryptbuff;
static enum ciphermode ciphermode;
static enum padding padding;

static union {
    struct aes_ctx aesctx;
    /*struct CBC_CTX(struct aes_ctx, 128/8) aes128cbc;*/
} keyctx;


enum typeofdata {
    JUNK = 0,
    TEXT = 1,
    BINARY = 2
};

/*
   No strange control characters = OK, probably text
   High number of zeros = OK, probably binary data
*/
enum typeofdata checkdata(const unsigned char *data, long len)
{
    long numzeros = 0;
    long numcontrol = 0;
    float rzero, rctrl;
    const unsigned char *p = data;
    const unsigned char *end = data+len;
    
    int i;
    char padsize = end[-1];
    if (padding == PKCS7) {
        if (padsize > AES_BLOCK_SIZE || padsize < 0) {
            return JUNK;
        }
        for (i = 0; i < padsize; i++) {
            if (end <= p || *--end != padsize) return JUNK;
        }
    } else if (padding == THROW_AWAY) {
        end -= AES_BLOCK_SIZE;
    }
    
    while (p < end) {
        unsigned char c = *(p++);
        if (c == '\0') {
            numzeros++;
        } else if (c >= '\x01' && c <= '\x1F' &&
                   c != '\x09' && c != '\x08' && c != '\x0A' && c != '\x0D') {
            numcontrol++;
        }
    }
    
    rzero = (float)numzeros / (float)len;
    rctrl = (float)numcontrol / (float)len;
    
    if (rzero >= 0.02) { /* >> 1/256 */
        return BINARY;
    } else if (rctrl <= 0.03) { /* << (32-4) / 256  */
        return TEXT;
    } else if (padding == PKCS7 && padsize >= 4) {
        return BINARY;
    } else {
        return JUNK;
    }
}

void decrypt(unsigned char *encrypted, long len, const unsigned char *key,
             unsigned char *decrypted)
{
    unsigned char iv[AES_BLOCK_SIZE];
    /* TODO use nettle-meta.h */
    switch (ciphermode) {
    case AES128_CBC:
        if (len < AES_BLOCK_SIZE) { abort(); }
        memcpy(iv, encrypted, AES_BLOCK_SIZE);
        aes_set_decrypt_key(&keyctx.aesctx, 128/8, key);
        cbc_decrypt(&keyctx.aesctx, (nettle_crypt_func *)aes_decrypt, AES_BLOCK_SIZE, iv,
                    len-AES_BLOCK_SIZE, decrypted, encrypted+AES_BLOCK_SIZE);
        break;
    case AES128_ECB:
        aes_set_decrypt_key(&keyctx.aesctx, 128/8, key);
        aes_decrypt(&keyctx.aesctx, len, decrypted, encrypted);
        break;
    case AES256_CBC:
        if (len < AES_BLOCK_SIZE) { abort(); }
        memcpy(iv, encrypted, AES_BLOCK_SIZE);
        aes_set_decrypt_key(&keyctx.aesctx, 256/8, key);
        cbc_decrypt(&keyctx.aesctx, (nettle_crypt_func *)aes_decrypt, AES_BLOCK_SIZE, iv,
                    len-AES_BLOCK_SIZE, decrypted, encrypted+AES_BLOCK_SIZE);
        break;
    case AES256_ECB:
        aes_set_decrypt_key(&keyctx.aesctx, 256/8, key);
        aes_decrypt(&keyctx.aesctx, len, decrypted, encrypted);
        break;
    default:
        abort();
    }
    /*putchar(key[128/8-1]);*/
}

int try_decrypt(long scan_offset, unsigned char *key)
{
    long files_text = 0, files_bin = 0;
    long i;
    
    for (i = 0; i < numfiles; i++) {
        const struct fileentry *entry = &files[i];
        enum typeofdata result;
        const long decryptlen = entry->datalen - cipher_iv_size[ciphermode];
        
/*if (*key == 0x4B && key[1] == 0x45 && key[2] == 0x59) {
fprintf(stderr, "found key at %ld\n", scan_offset);
fprintf(stderr, "file = %hhx %hhx %hhx %hhx\n", entry->data[0], entry->data[1], entry->data[2], entry->data[3]);
}*/
        decrypt(entry->data, entry->datalen, key, decryptbuff);
/*if (*key == 0x4B && key[1] == 0x45 && key[2] == 0x59) {
fprintf(stderr, "data = %.*s\n", decryptlen, decryptbuff);
}*/
        
/*result = 0;
if (*key == 0x4B && key[1] == 0x45 && key[2] == 0x59) {*/
        result = checkdata(decryptbuff, decryptlen);
/*fprintf(stderr, "result = %d\n", result);
}*/
        
        if (result == JUNK) return 0;
        
        if (result == BINARY) files_bin++;
        else files_text++;
    }
    
    printf("%ld: found key (decrypted data = %ld text, %ld binary)\n",
           scan_offset, files_text, files_bin);
    return 0;
}

void do_scan_file()
{
    unsigned char keybuff[2*READSIZE];
    unsigned long scan_offset = 0;
    const unsigned long keysize = cipher_key_size[ciphermode];
    
    size_t numbytes = fread(keybuff, 1, READSIZE, scanfile);
    if (numbytes != READSIZE && ferror(scanfile)) {
        perror("scan file too short");
        exit(1);
    }
    
    /* Scan the first half of the buffer and move in more data.
       This is done so we can handle keys that overlap a READSIZE
       boundary. */
    while (!feof(scanfile)) {
        unsigned long keyoffs = 0;
        int nonzeros = keysize;
        
        if ((scan_offset & 0xFFFFFL) == 0) {
            fprintf(stderr, "Scanned %ld bytes\n", scan_offset);
        }
        
        numbytes += fread(keybuff+READSIZE, 1, READSIZE, scanfile);
        while (numbytes > READSIZE) {
            if (keybuff[keyoffs+keysize]) {
                nonzeros = keysize;
            }
            
            if (nonzeros) {
                try_decrypt(scan_offset, &keybuff[keyoffs]);
            }
            numbytes--;
            scan_offset++;
            keyoffs++;
            if (nonzeros) nonzeros--;
        }
        memcpy(keybuff, keybuff+READSIZE, READSIZE);
    }
    
    /* Scan the remaining data */
    {
        unsigned long keyoffs = 0;
        while (numbytes > keysize) {
            try_decrypt(scan_offset, &keybuff[keyoffs]);
            numbytes--;
            scan_offset++;
            keyoffs++;
        }
        fprintf(stderr, "Scanned %ld bytes\n", scan_offset);
    }
}

void show_usage(const char *arg0)
{
    printf("usage: %s -s FILE_TO_SCAN [-o OFFSET] [-l LEN] FILES...\n"
           "\n"
           "Tries to decrypt the given FILES with AES-128/256 using all 128/256-bit\n"
           "substrings in FILE_TO_SCAN.\n"
           "\n"
           "Options:\n"
           "   -c CIPHER   Set the cipher to use:\n"
           "                    0   AES128 with CBC (default)\n"
           "                    1   AES128 with ECB\n"
           "                    2   AES256 with CBC\n"
           "                    3   AES256 with ECB\n"
           "   -p PADDING  Set the padding to use:\n"
           "                    0   PKCS#5 (default)\n"
           "                    1   Simply throw away the last block\n"
           "                    2   No padding\n"
           "   -l LEN      Try to decrypt only up to LEN bytes in the FILES\n"
           "   -o OFFSET   Start from the given byte offset in the FILES\n"
           "\n"
           "Note: The -o and -l options are parsed from left to right. An -o\n"
           "or -l option must occur before the file(s) it should to apply to.\n"
           "\n",
           arg0);
}

long get_num(int argc, char **argv, int *idxp)
{
    int i = *idxp;
    long value;
    char *s, *endp;
    
    if (i+1 >= argc) {
        fprintf(stderr, "%s: option requires an argument\n", argv[i]);
        exit(2);
    }
    
    s = argv[i+1];
    value = strtol(s, &endp, 10);
    if (*s == '\0' || *endp != '\0' || value < 0) {
        fprintf(stderr, "%s: invalid number\n", s);
        exit(2);
    }
    
    *idxp = i+1;
    return value;
}

char *get_str(int argc, char **argv, int *idxp)
{
    int i = *idxp;
    
    if (i+1 >= argc) {
        fprintf(stderr, "%s: option requires an argument\n", argv[i]);
        exit(2);
    }
    
    *idxp = i+1;
    return argv[i+1];
}

int main(int argc, char **argv)
{
    int parsing_opts = 1, error = 0;
    int i;
    long maxdatalen;
    for (i = 1; i < argc; i++) {
        char *const arg = argv[i];
        if (arg[0] == '-' && parsing_opts) {
            /* Option */
            if (arg[1] == '-' && arg[2] == '\0') {
                /* "--" = stop parsing arguments */
                parsing_opts = 0;
                continue;
            }
            if (arg[1] != '\0' && arg[2] == '\0') {
                switch (arg[1]) {
                case 'c': /*{
                    const char *s = get_str(argc, argv, &i);
                    if (strcmp
                    break; }*/
                    ciphermode = get_num(argc, argv, &i);
                    if (ciphermode > AES256_ECB) {
                        fprintf(stderr, "%s: invalid cipher type %d\n",
                                argv[0], ciphermode);
                        error = 1;
                    }
                    break;
                case 'h':
                    show_usage(argv[0]);
                    return 0;
                case 'l':
                    maxlength = get_num(argc, argv, &i);
                    break;
                case 'o':
                    offset = get_num(argc, argv, &i);
                    break;
                case 'p':
                    padding = get_num(argc, argv, &i);
                    if (padding > NO_PADDING) {
                        fprintf(stderr, "%s: invalid paddig type %d\n",
                                argv[0], padding);
                        error = 1;
                    }
                    break;
                case 's':
                    scanfilename = get_str(argc, argv, &i);
                    break;
                }
            }
        } else {
            /* Filename */
            unsigned char *data;
            long datalen;
            struct fileentry *entry;
            FILE *file = fopen(arg, "rb");
            if (!file) {
                perror(arg);
                error = 1;
                continue;
            }
            
            if (offset) {
                if (fseek(file, offset, SEEK_SET) == -1) {
                    perror(arg);
                    exit(1);
                }
            }
            
            if (!maxlength) {
                /* Read the whole file */
                if (fseek(file, 0, SEEK_END) == -1) {
                    perror(arg);
                    exit(1);
                }
                
                datalen = ftell(file) - offset;
                if (datalen < 0) {
                    perror("ftell");
                    exit(1);
                }
                
                data = malloc(datalen);
                if (!data) {
                    perror("allocating memory for file");
                    exit(1);
                }
                
                if (fseek(file, offset, SEEK_SET) == -1) {
                    perror(arg);
                    exit(1);
                }
            }
            
            if (fread(data, 1, datalen, file) != (size_t)datalen) {
                perror(arg);
                exit(1);
            }
            
            fclose(file);
            
            if (datalen == 0) {
                fprintf(stderr, "%s: File is empty\n", arg);
                exit(1);
            }
            
            numfiles++;
            files = realloc(files, sizeof(struct fileentry)*numfiles);
            if (!files) {
                perror("realloc");
                exit(1);
            }
            entry = &files[numfiles-1];
            entry->name = arg;
            entry->data = data;
            entry->datalen = datalen;
        }
    }
    
    if (error) {
        return 1;
    }
    
    if (!numfiles) {
        fprintf(stderr, "%s: no files specified\n", argv[0]);
        show_usage(argv[0]);
        return 2;
    }
    
    if (!scanfilename) {
        fprintf(stderr, "%s: no scan file specified\n", argv[0]);
        return 2;
    }
    
    /* Allocate buffer for decryption */
    maxdatalen = 0;
    for (i = 0; i < numfiles; i++) {
        if (files[i].datalen > maxdatalen) {
            maxdatalen = files[i].datalen;
        }
    }
    decryptbuff = malloc(maxdatalen);
    
    fprintf(stderr, "Using %s cipher and mode, with padding %s\n",
            ciphermodes[ciphermode], paddings[padding]);
    
    /* Start scanning the file for keys */
    scanfile = fopen(scanfilename, "rb");
    if (!scanfile) {
        perror(scanfilename);
        exit(1);
    }
    
    do_scan_file();
    
    fclose(scanfile);
    
    return 0;
}

