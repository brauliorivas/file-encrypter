# Encrypter

> [!NOTE]
> El binario generado se guardará en la carpeta `bin/` tras compilar con `make`.

Bienvenido a Encrypter, un programa que encripta o desencripta un archivo usando los algoritmos AES o BLOWFISH.

## Uso

```bash
./encrypter [-d] [-a <algo>] [-b <bits>] -k <passphrase> <nombre_archivo>
./encrypter -h
```

## Opciones

-   `-h` Ayuda, muestra este mensaje
-   `-d` Desencripta el archivo en lugar de encriptarlo.
-   `-k <passphrase>` Especifica la frase de encriptación.
-   `-a <algo>` Especifica el algoritmo de encriptación, opciones: aes, blowfish. [default: aes]
-   `-b <bits>` Especifica los bits de encriptación, opciones: 128, 192, 256. [default: 128]

## Ejemplos

```bash
./encrypter -a blowfish -b 256 -k mifrasesecreta documento.txt

Usando blowfish con clave de 256 bits...
Archivo documento.txt encriptado exitosamente en documento.txt.enc...
```

```bash
./encrypter -k "mi super frase secreta" documento.txt

Usando aes con clave de 128 bits...
Archivo documento.txt encriptado exitosamente en documento.txt.enc...
```

```bash
./encrypter -d -k mifrasesecreta documento.txt.enc

Usando blowfish con clave de 256 bits...
Archivo documento.txt.enc desencriptado exitosamente en documento.txt...
```

En este último ejemplo, nos podemos dar cuenta que `encrypter` detecta automáticamente el algoritmo y los bits de encriptación a utilizar.

## Funcionamiento

### Makefile

El `Makefile` contiene las reglas necesarias para compilar el programa de forma dinámica. Automáticamente, si una nueva librería es añadida o un nuevo archivo fuente, el `Makefile` se encargará de compilarlo.
Para las librerías, se compilan de forma estática.

### Cabecera

Cada vez que se encripta un archivo, se añaden datos al principio del archivo encriptado. Estos datos son necesarios para desencriptar el archivo. La estructura de estos datos es la siguiente:

`byte 0|byte 1|byte 2|byte 3|byte 4|byte 5|byte 6|byte 7|mask`

Los bytes del 0 al 7 son para indicar el tamaño del archivo original. Y la máscara es un byte que indica el algoritmo y los bits de encriptación utilizados.
