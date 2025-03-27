# Encrypter

> [!NOTE]
> The generated binary will be saved in the `bin/` folder after compiling with `make`.

Welcome to Encrypter, a program that encrypts or decrypts a file using the AES or BLOWFISH algorithms.

## Usage

```bash
./encrypter [-d] [-a <algo>] [-b <bits>] -k <passphrase> <filename>
./encrypter -h
```

## Options

-   `-h` Help, displays this message.
-   `-d` Decrypts the file instead of encrypting it.
-   `-k <passphrase>` Specifies the encryption passphrase.
-   `-a <algo>` Specifies the encryption algorithm, options: aes, blowfish. [default: aes]
-   `-b <bits>` Specifies the encryption bits, options: 128, 192, 256. [default: 128]

## Examples

```bash
./encrypter -a blowfish -b 256 -k mifrasesecreta documento.txt

Using blowfish with a 256-bit key...
File documento.txt successfully encrypted to documento.txt.enc...
```

```bash
./encrypter -k "mi super frase secreta" documento.txt

Using aes with a 128-bit key...
File documento.txt successfully encrypted to documento.txt.enc...
```

```bash
./encrypter -d -k mifrasesecreta documento.txt.enc

Using blowfish with a 256-bit key...
File documento.txt.enc successfully decrypted to documento.txt...
```

In the last example, we can see that `encrypter` automatically detects the algorithm and encryption bits to use.

## How it Works

### Makefile

The `Makefile` contains the necessary rules to compile the program dynamically. Automatically, if a new library is added or a new source file is introduced, the `Makefile` will handle the compilation. 
For libraries, static libraries are created.

### Header

Each time a file is encrypted, data is added at the beginning of the encrypted file. This data is needed to decrypt the file. The structure of this data is as follows:

`byte 0|byte 1|byte 2|byte 3|byte 4|byte 5|byte 6|byte 7|mask`

Bytes 0 to 7 indicate the size of the original file. The mask is a byte that indicates the algorithm and the encryption bits used.
