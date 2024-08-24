#ifndef ENCRYPTER_H
#define ENCRYPTER_H

#define _FILE_OFFSET_BITS 64

#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <unistd.h>
#include "errors.h"
#include "sha256.h"
#include "aes.h"
#include "blowfish.h"

#define AES 0x10
#define BLOWFISH 0x20
#define KEY_128 0x01
#define KEY_192 0x02
#define KEY_256 0x04

bool is_valid_bit(int);
bool is_valid_algorithm(char *);

int generate_key_sha256(char *, BYTE *, int);

void encrypt_file(char *, int, char *, char *);
void decrypt_file(char *, char *);

#endif // ENCRYPTER_H