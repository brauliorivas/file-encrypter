#include "encrypter.h"

/**
 * Number of bits available for encryption
 *
 * 128, 192, 256
 */
int available_bits[] = {128, 192, 256};

/**
 * Available encryption algorithms
 *
 * aes, blowfish
 */
char *available_algorithms[] = {"aes", "blowfish"};

/**
 * Checks if the number of bits is valid. Valid values are 128, 192, and 256.
 *
 * @param bit Number of bits
 *
 * @return true if the number of bits is valid, false otherwise
 */
bool is_valid_bit(int bit)
{
    int length = sizeof(available_bits) / sizeof(available_bits[0]);
    for (int i = 0; i < length; i++)
    {
        if (available_bits[i] == bit)
        {
            return true;
        }
    }

    return false;
}

/**
 * Checks if the encryption algorithm is valid. Valid values are aes and blowfish.
 *
 * @param algorithm Encryption algorithm
 *
 * @return true if the algorithm is valid, false otherwise
 */
bool is_valid_algorithm(char *algorithm)
{
    int length = sizeof(available_algorithms) / sizeof(available_algorithms[0]);
    for (int i = 0; i < length; i++)
    {
        if (strcmp(algorithm, available_algorithms[i]) == 0)
        {
            return true;
        }
    }

    return false;
}

/**
 * Generates an encryption key from a phrase
 *
 * @param phrase Encryption phrase, i.e., textual password
 * @param key Byte array where the generated key will be stored
 * @param n_bits Key size in bits. If it is less than 256 bits, the key will be truncated.
 */
int generate_key_sha256(char *phrase, BYTE *key, int n_bits)
{
    BYTE hash[SHA256_BLOCK_SIZE];
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, (BYTE *)phrase, strlen(phrase));
    sha256_final(&ctx, hash);
    for (int i = 0; i < (n_bits / 8); i++)
    {
        key[i] = hash[i];
    }
}

/**
 * Encrypts a file
 *
 * @param algorithm Encryption algorithm
 * @param bits Key size in bits
 * @param passphrase Encryption phrase
 * @param file_name Name of the file to encrypt
 */
void encrypt_file(char *algorithm, int bits, char *passphrase, char *file_name)
{
    int original_file_fd = open(file_name, O_RDONLY, S_IRUSR);

    if (original_file_fd < 0)
    {
        print_error("Error reading the file to encrypt");
        exit(1);
    }

    struct stat file_stats;
    if ((stat(file_name, &file_stats) < 0))
    {
        print_error("Error obtaining the file size");
        exit(1);
    }

    off_t file_size = file_stats.st_size;

    BYTE size_bytes[8] = {0};

    // Convert the file size to bytes to write it in the header in Little Endian format
    for (int i = 0; i < 8; i++)
    {
        BYTE byte = (file_size >> 8 * (i)) & 0xFF;
        size_bytes[i] = byte;
    }

    BYTE mask = 0x00;

    if (bits == 128)
    {
        mask |= KEY_128;
    }
    else if (bits == 192)
    {
        mask |= KEY_192;
    }
    else
    {
        mask |= KEY_256;
    }

    char extension[] = ".enc";
    char *new_file_name = (char *)malloc(strlen(file_name) + strlen(extension));
    strcpy(new_file_name, file_name);
    strcat(new_file_name, extension);

    int new_file_fd = open(new_file_name, O_CREAT | O_TRUNC | O_RDWR, S_IRUSR | S_IWUSR);

    if (new_file_fd < 0)
    {
        print_error("Error creating the encrypted file");
        exit(1);
    }

    ssize_t write_size = sizeof(BYTE) * 8;
    ssize_t bytes_written = write(new_file_fd, size_bytes, write_size);
    if (bytes_written != write_size)
    {
        print_error("Error writing the header");
        exit(1);
    }

    BYTE *encrypt_key;
    encrypt_key = (BYTE *)malloc(sizeof(BYTE) * bits);
    generate_key_sha256(passphrase, encrypt_key, bits);

    if (strcmp(algorithm, "aes") == 0)
    {
        mask |= AES;
        ssize_t bytes_mask_written = write(new_file_fd, &mask, sizeof(BYTE));
        if (bytes_mask_written != sizeof(BYTE))
        {
            print_error("Error writing the header");
            exit(1);
        }

        WORD key_schedule[60];
        BYTE aes_buffer[AES_BLOCK_SIZE];
        BYTE read_buffer[AES_BLOCK_SIZE] = {0};

        aes_key_setup(encrypt_key, key_schedule, bits);

        while (read(original_file_fd, read_buffer, AES_BLOCK_SIZE) > 0)
        {
            aes_encrypt(read_buffer, aes_buffer, key_schedule, bits);
            if (write(new_file_fd, aes_buffer, AES_BLOCK_SIZE) == -1)
            {
                print_error("Error writing the encrypted file");
                exit(1);
            }
            memset(read_buffer, 0, sizeof(read_buffer));
        }
    }
    else
    {
        mask |= BLOWFISH;
        ssize_t bytes_mask_written = write(new_file_fd, &mask, sizeof(BYTE));
        if (bytes_mask_written != sizeof(BYTE))
        {
            print_error("Error writing the header");
            exit(1);
        }

        BLOWFISH_KEY key;
        BYTE enc_buf[BLOWFISH_BLOCK_SIZE];
        BYTE read_buffer[BLOWFISH_BLOCK_SIZE] = {0};

        blowfish_key_setup(encrypt_key, &key, bits / 8);

        while (read(original_file_fd, read_buffer, BLOWFISH_BLOCK_SIZE) > 0)
        {
            blowfish_encrypt(read_buffer, enc_buf, &key);
            if (write(new_file_fd, enc_buf, BLOWFISH_BLOCK_SIZE) == -1)
            {
                print_error("Error writing the encrypted file");
                exit(1);
            }
            memset(read_buffer, 0, sizeof(read_buffer));
        }
    }

    printf("File %s successfully encrypted as %s\n", file_name, new_file_name);

    free(new_file_name);
    free(encrypt_key);
}

/**
 * Decrypts a file
 *
 * @param passphrase Encryption phrase
 * @param file_name Name of the file to decrypt
 */
void decrypt_file(char *passphrase, char *file_name)
{

    int original_file_fd = open(file_name, O_RDONLY, S_IRUSR);

    if (original_file_fd < 0)
    {
        print_error("Error reading the file to decrypt\n");
        exit(1);
    }

    char *extension = strstr(file_name, ".enc");

    if (extension == NULL)
    {
        print_error("Invalid file name: file without .enc extension\n");
        exit(1);
    }

    unsigned long long original_file_size = 0;
    BYTE size_bytes[8] = {0};

    // Read the file size in bytes
    BYTE byte = 0x00;
    for (int i = 0; i < 8; i++)
    {
        if (read(original_file_fd, &byte, sizeof(BYTE)) == -1)
        {
            print_error("Error reading the file size\n");
            exit(1);
        }
        size_bytes[i] = byte;
    }

    // Convert the file size to a 64-bit integer.
    int i;
    for (i = 7; i > 0; i--)
    {
        original_file_size = original_file_size | size_bytes[i];
        original_file_size = original_file_size << 8;
    }

    original_file_size = original_file_size | size_bytes[i];

    BYTE mask = 0x00;
    if (read(original_file_fd, &mask, sizeof(BYTE)) == -1)
    {
        print_error("Error reading the header\n");
        exit(1);
    }

    printf("Using %s with a %d-bit key\n", algorithm, bits);

    printf("File %s successfully decrypted as %s\n", file_name, new_file_name);

    free(new_file_name);
    free(encrypt_key);
    ftruncate(new_file_fd, original_file_size);
}
