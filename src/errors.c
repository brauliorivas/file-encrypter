#include "errors.h"

/**
 * Imprime un mensaje de error
 *
 * @param message_error Mensaje de error
 */
void print_error(char message_error[])
{
    fprintf(stderr, message_error);
}