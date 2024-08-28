#include "encrypter.h"

/**
 * Número de bits disponibles para encriptación
 *
 * 128, 192, 256
 */
int available_bits[] = {128, 192, 256};

/**
 * Algoritmos de encriptación disponibles
 *
 * aes, blowfish
 */
char *available_algorithms[] = {"aes", "blowfish"};

/**
 * Verifica si el número de bits es válido. Los valores válidos son 128, 192 y 256
 *
 * @param bit Número de bits
 *
 * @return true si el número de bits es válido, false en caso contrario
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
 * Verifica si el algoritmo de encriptación es válido. Los valores válidos son aes y blowfish
 *
 * @param algorithm Algoritmo de encriptación
 *
 * @return true si el algoritmo es válido, false en caso contrario
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
 * Genera una clave de encriptación a partir de una frase
 *
 * @param phrase Frase de encriptación, es decir contraseña textual
 * @param key Arreglo de bytes donde se almacenará la clave generada
 * @param n_bits Número de bits de la clave. Si es menor a 256 bits, se truncará la clave
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
 * Encripta un archivo
 *
 * @param algorithm Algoritmo de encriptación
 * @param bits Número de bits de la clave
 * @param passphrase Frase de encriptación
 * @param file_name Nombre del archivo a encriptar
 */
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

    // Convertir el tamaño del archivo a bytes para escribirlo en la cabecera en formato Little Endian
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
            if (write(new_file_fd, aes_buffer, AES_BLOCK_SIZE) == -1)
            {
                print_error("Error al escribir el archivo encriptado");
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
            if (write(new_file_fd, enc_buf, BLOWFISH_BLOCK_SIZE) == -1)
            {
                print_error("Error al escribir el archivo encriptado");
                exit(1);
            }
            memset(read_buffer, 0, sizeof(read_buffer));
        }
    }

    printf("Archivo %s encriptado exitosamente en %s\n", file_name, new_file_name);

    free(new_file_name);
    free(encrypt_key);
}

/**
 * Desencripta un archivo
 *
 * @param passphrase Frase de encriptación
 * @param file_name Nombre del archivo a desencriptar
 */
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

    // Leer el tamaño del archivo en bytes
    BYTE byte = 0x00;
    for (int i = 0; i < 8; i++)
    {
        if (read(original_file_fd, &byte, sizeof(BYTE)) == -1)
        {
            print_error("Error al leer el tamaño del archivo\n");
            exit(1);
        }
        size_bytes[i] = byte;
    }

    // Convertir el tamaño del archivo a entero de 64 bits.
    // Primero se lee el byte más significativo, se almacena en el byte
    // menos significativo de la variable original_file_size y se desplaza
    // 8 bits a la izquierda.
    // Se repite el proceso hasta leer el byte menos significativo.
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
        print_error("Error al leer la cabecera\n");
        exit(1);
    }

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
            if (write(new_file_fd, aes_buffer, AES_BLOCK_SIZE) == -1)
            {
                print_error("Error al escribir el archivo desencriptado");
                exit(1);
            }
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
            if (write(new_file_fd, enc_buf, BLOWFISH_BLOCK_SIZE) == -1)
            {
                print_error("Error al escribir el archivo desencriptado");
                exit(1);
            }
        }
    }

    printf("Archivo %s desencriptado exitosamente en %s\n", file_name, new_file_name);

    free(new_file_name);
    free(encrypt_key);
    ftruncate(new_file_fd, original_file_size);
}