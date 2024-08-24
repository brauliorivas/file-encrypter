#include <stdio.h>
#include <getopt.h>
#include <stdbool.h>
#include <string.h>
#include "errors.h"
#include "encrypter.h"

/**
 * Imprime la ayuda del programa
 *
 * @param executable Nombre del ejecutable
 *
 */
void print_help(char *executable)
{
    printf("%s encripta o desencripta un archivo usando los algoritmos AES o BLOWFISH.\n", executable);
    printf("uso:\n");
    printf(" ./encrypter [-d] [-a <algo>] [-b <bits>] -k <passphrase> <nombre_archivo>\n");
    printf(" ./encrypter -h\n");
    printf("Opciones:\n");
    printf(" -h\t\t\tAyuda, muestra este mensaje\n");
    printf(" -d\t\t\tDesencripta el archivo en lugar de encriptarlo.\n");
    printf(" -k <passphrase>\tEspecifica la frase de encriptación.\n");
    printf(" -a <algo>\t\tEspecifica el algoritmo de encriptación, opciones: aes, blowfish. [default: aes]\n");
    printf(" -b <bits>\t\tEspecifica los bits de encriptación, opciones: 128, 192, 256. [default: 128]\n");
}

int main(int argc, char *argv[])
{
    char *executable = argv[0];
    int opt;
    int arguments = 1;
    bool decrypt = false;
    char *algorithm = "aes";
    int bits = 128;
    char *passphrase;
    bool has_passphrase = false;

    while ((opt = getopt(argc, argv, "hda:b:k:")) != -1)
    {
        switch (opt)
        {
        case 'h':
            print_help(executable);
            return 0;
        case 'd':
            decrypt = true;
            arguments += 1;
            break;
        case 'a':
            algorithm = optarg;
            arguments += 2;
            break;
        case 'b':
            bits = atoi(optarg);
            arguments += 2;
            break;
        case 'k':
            passphrase = optarg;
            arguments += 2;
            has_passphrase = true;
            break;
        default:
            print_error("Opción inválida\n");
            print_help(executable);
            return 1;
        }
    }

    if (!is_valid_algorithm(algorithm))
    {
        fprintf(stderr, "Algoritmo de encriptación no soportado: %s", algorithm);
        printf("Algoritmos soportados: aes, blowfish");
        return 1;
    }

    if (!is_valid_bit(bits))
    {
        fprintf(stderr, "Número de bits de encriptación no soportado: %d", bits);
        printf("Usar: 128, 192 o 256");
        return 1;
    }

    if (!has_passphrase)
    {
        print_error("Passphrase es requerido\n");
        return 1;
    }

    else
    {
        if (argc < (arguments + 1))
        {
            print_error("No se pasaron la cantidad suficiente de argumentos\n");
            print_help(executable);
            return 1;
        }
    }

    char *file_name;
    for (int i = 0; i < argc; i++)
    {
        file_name = argv[i];
    }

    if (decrypt)
    {
        decrypt_file(passphrase, file_name);
    }
    else
    {
        printf("Usando %s con clave de %d bits\n", algorithm, bits);
        encrypt_file(algorithm, bits, passphrase, file_name);
    }

    return 0;
}