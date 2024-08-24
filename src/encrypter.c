#include "encrypter.h"

int available_bits[] = {128, 192, 256};
char *available_algorithms[] = {"aes", "blowfish"};

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

void encrypt_file(char *algorithm, int bits, char *passphrase, char *file_name)
{
    int original_file_fd = open(file_name, O_RDONLY, S_IRUSR);

    if (original_file_fd < 0)
    {
        print_error("Error al leer el archivo a encriptar");
        exit(1);
    }

    struct stat file_stats;
    if ((stat(file_name, &file_stats) < 0))
    {
        print_error("Error al obtener el tamaño del archivo");
        exit(1);
    }

    off_t file_size = file_stats.st_size;

    BYTE size_bytes[8] = {0};

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
        print_error("Error al crear el archivo encriptado");
        exit(1);
    }

    ssize_t write_size = sizeof(BYTE) * 8;
    ssize_t bytes_written = write(new_file_fd, size_bytes, write_size);
    if (bytes_written != write_size)
    {
        print_error("Error al escribir la cabecera");
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
            print_error("Error al escribir la cabecera");
            exit(1);
        }

        WORD key_schedule[60];
        BYTE aes_buffer[AES_BLOCK_SIZE];
        BYTE read_buffer[AES_BLOCK_SIZE] = {0};

        aes_key_setup(encrypt_key, key_schedule, bits);

        while (read(original_file_fd, read_buffer, AES_BLOCK_SIZE) > 0)
        {
            aes_encrypt(read_buffer, aes_buffer, key_schedule, bits);
            write(new_file_fd, aes_buffer, AES_BLOCK_SIZE);
            memset(read_buffer, 0, sizeof(read_buffer));
        }
    }
    else
    {
        mask |= BLOWFISH;
        ssize_t bytes_mask_written = write(new_file_fd, &mask, sizeof(BYTE));
        if (bytes_mask_written != sizeof(BYTE))
        {
            print_error("Error al escribir la cabecera");
            exit(1);
        }

        BLOWFISH_KEY key;
        BYTE enc_buf[BLOWFISH_BLOCK_SIZE];
        BYTE read_buffer[BLOWFISH_BLOCK_SIZE] = {0};

        blowfish_key_setup(encrypt_key, &key, bits / 8);

        while (read(original_file_fd, read_buffer, BLOWFISH_BLOCK_SIZE) > 0)
        {
            blowfish_encrypt(read_buffer, enc_buf, &key);
            write(new_file_fd, enc_buf, BLOWFISH_BLOCK_SIZE);
            memset(read_buffer, 0, sizeof(read_buffer));
        }
    }

    printf("Archivo %s encriptado exitosamente en %s\n", file_name, new_file_name);

    free(new_file_name);
    free(encrypt_key);
}

void decrypt_file(char *passphrase, char *file_name)
{

    int original_file_fd = open(file_name, O_RDONLY, S_IRUSR);

    if (original_file_fd < 0)
    {
        print_error("Error al leer el archivo a desencriptar\n");
        exit(1);
    }

    char *extension = strstr(file_name, ".enc");

    if (extension == NULL)
    {
        print_error("Nombre de archivo no valido: archivo sin extensión .enc\n");
        exit(1);
    }

    unsigned long long original_file_size = 0;
    BYTE size_bytes[8] = {0};

    BYTE byte = 0x00;
    for (int i = 0; i < 8; i++)
    {
        read(original_file_fd, &byte, sizeof(BYTE));
        size_bytes[i] = byte;
    }

    int i;
    for (i = 7; i > 0; i--)
    {
        original_file_size = original_file_size | size_bytes[i];
        original_file_size = original_file_size << 8;
    }

    original_file_size = original_file_size | size_bytes[i];

    BYTE mask = 0x00;
    read(original_file_fd, &mask, sizeof(BYTE));

    int bits = 0;
    if ((mask & KEY_128) == KEY_128)
    {
        bits = 128;
    }
    else if ((mask & KEY_192) == KEY_192)
    {
        bits = 192;
    }
    else if ((mask & KEY_256) == KEY_256)
    {
        bits = 256;
    }
    else
    {
        print_error("Cabecera no especifica número de bits de clave correctamente\n");
        exit(1);
    }

    char *algorithm;

    if ((mask & AES) == AES)
    {
        char str[] = "aes";
        algorithm = str;
    }
    else if ((mask & BLOWFISH) == BLOWFISH)
    {
        char str[] = "blowfish";
        algorithm = str;
    }
    else
    {
        print_error("Cabecera no especifica algoritmo de encriptación correctamente\n");
        exit(1);
    }

    printf("Usando %s con clave de %d bits\n", algorithm, bits);

    ssize_t file_name_size = strlen(file_name) - strlen(extension);
    char *new_file_name = (char *)malloc(file_name_size);
    memcpy(new_file_name, file_name, file_name_size);

    int new_file_fd = open(new_file_name, O_CREAT | O_TRUNC | O_RDWR, S_IRUSR | S_IWUSR);

    BYTE *encrypt_key;
    encrypt_key = (BYTE *)malloc(sizeof(BYTE) * bits);
    generate_key_sha256(passphrase, encrypt_key, bits);

    if (strcmp(algorithm, "aes") == 0)
    {
        WORD key_schedule[60];
        BYTE aes_buffer[AES_BLOCK_SIZE];
        BYTE read_buffer[AES_BLOCK_SIZE] = {0};

        aes_key_setup(encrypt_key, key_schedule, bits);

        while (read(original_file_fd, read_buffer, AES_BLOCK_SIZE) > 0)
        {
            aes_decrypt(read_buffer, aes_buffer, key_schedule, bits);
            write(new_file_fd, aes_buffer, AES_BLOCK_SIZE);
        }
    }
    else
    {
        BLOWFISH_KEY key;
        BYTE enc_buf[BLOWFISH_BLOCK_SIZE];
        BYTE read_buffer[BLOWFISH_BLOCK_SIZE] = {0};

        blowfish_key_setup(encrypt_key, &key, bits / 8);

        while (read(original_file_fd, read_buffer, BLOWFISH_BLOCK_SIZE) > 0)
        {
            blowfish_decrypt(read_buffer, enc_buf, &key);
            write(new_file_fd, enc_buf, BLOWFISH_BLOCK_SIZE);
        }
    }

    printf("Archivo %s desencriptado exitosamente en %s\n", file_name, new_file_name);

    free(new_file_name);
    free(encrypt_key);
    ftruncate(new_file_fd, original_file_size);
}