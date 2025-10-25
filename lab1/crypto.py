#!/usr/bin/env python3 -tt
"""
File: crypto.py
---------------
Assignment 1: Cryptography
Course: CS 41
Name: <YOUR NAME>
SUNet: <SUNet ID>

Replace this with a description of the program.
"""
import utils

# Caesar Cipher


def encrypt_caesar(plaintext):
    """Encrypt plaintext using a Caesar cipher."""
    n = len(plaintext)
    new_text = ""
    for i in range(n):
        if ord(plaintext[i]) > 64 and ord(plaintext[i]) < 91:
            new_text = new_text + chr(((ord(plaintext[i]) - 65) + 3) % 26 + 65)
        elif ord(plaintext[i]) > 96 and ord(plaintext[i]) < 123:
            new_text = new_text + chr(((ord(plaintext[i]) - 97) + 3) % 26 + 97)
        else:
            new_text = new_text + plaintext[i]
    return new_text


def decrypt_caesar(ciphertext):
    """Decrypt a ciphertext using a Caesar cipher."""
    n = len(ciphertext)
    new_text = ""
    for i in range(n):
        if ord(ciphertext[i]) > 64 and ord(ciphertext[i]) < 91:
            new_text = new_text + chr(((ord(ciphertext[i]) - 65) - 3) % 26 + 65)
        elif ord(ciphertext[i]) > 96 and ord(ciphertext[i]) < 123:
            new_text = new_text + chr(((ord(ciphertext[i]) - 97) - 3) % 26 + 97)
        else:
            new_text = new_text + ciphertext[i]
    return new_text


# Vigenere Cipher


def encrypt_vigenere(plaintext, keyword):
    """Encrypt plaintext using a Vigenere cipher with a keyword."""

    keyword = keyword.upper()
    n = len(plaintext)
    m = len(keyword)
    new_text = ""
    for i in range(n):
        if ord(plaintext[i]) > 64 and ord(plaintext[i]) < 91:
            new_text = new_text + chr(
                ((ord(plaintext[i]) - 65) + (ord(keyword[i % m]) - 65)) % 26 + 65
            )
        elif ord(plaintext[i]) > 96 and ord(plaintext[i]) < 123:
            new_text = new_text + chr(
                ((ord(plaintext[i]) - 97) + (ord(keyword[i % m]) - 65)) % 26 + 97
            )
        else:
            new_text = new_text + plaintext[i]
    return new_text


def decrypt_vigenere(ciphertext, keyword):
    """Decrypt ciphertext using a Vigenere cipher with a keyword."""

    keyword = keyword.upper()
    n = len(ciphertext)
    m = len(keyword)
    new_text = ""
    for i in range(n):
        if ord(ciphertext[i]) > 64 and ord(ciphertext[i]) < 91:
            new_text = new_text + chr(
                ((ord(ciphertext[i]) - 65) - (ord(keyword[i % m]) - 65)) % 26 + 65
            )
        elif ord(ciphertext[i]) > 96 and ord(ciphertext[i]) < 123:
            new_text = new_text + chr(
                ((ord(ciphertext[i]) - 97) - (ord(keyword[i % m]) - 65)) % 26 + 97
            )
        else:
            new_text = new_text + ciphertext[i]
    return new_text


def encrypt_scytale(plaintext, circumference):
    if circumference == 1:
        return plaintext

    n = len(plaintext)

    if circumference >= n:
        return plaintext

    new_text = ""
    matrix = [[" " for _ in range(n)] for _ in range(circumference)]
    i = 0
    for j in range(n):
        matrix[i][j] = plaintext[j]
        i += 1
        if (j + 1) % circumference == 0:
            i = 0

    for i in matrix:
        print(i)
    for i in range(circumference):
        for j in range(n):
            if matrix[i][j] != " ":
                new_text = new_text + matrix[i][j]

    return new_text


def decrypt_scytale(ciphertext, circumference):
    if circumference == 1:
        return ciphertext

    n = len(ciphertext)

    if circumference >= n:
        return ciphertext

    n = len(ciphertext)
    new_text = ""
    matrix = [[" " for _ in range(n)] for _ in range(circumference)]
    i = 0
    j = 0
    for x in range(n):
        matrix[i][j] = ciphertext[x]
        if j + circumference >= n:
            i += 1
            j = i
        else:
            j += circumference

    for i in matrix:
        print(i)
    for j in range(n):
        for i in range(circumference):
            if matrix[i][j] != " ":
                new_text = new_text + matrix[i][j]

    return new_text


def encrypt_railfence(plaintext, num_rails):
    if num_rails == 1:
        return plaintext

    n = len(plaintext)

    if num_rails >= n:
        return plaintext

    new_text = ""
    matrix = [[" " for _ in range(n)] for _ in range(num_rails)]
    i = 0
    k = -1
    for j in range(n):
        matrix[i][j] = plaintext[j]
        if j % (num_rails - 1) == 0:
            k = -k
        i = i + k

    for i in matrix:
        print(i)
    for i in range(num_rails):
        for j in range(n):
            if matrix[i][j] != " ":
                new_text = new_text + matrix[i][j]

    return new_text


def decrypt_railfence(ciphertext, num_rails):
    if num_rails == 1:
        return ciphertext

    n = len(ciphertext)

    if num_rails >= n:
        return ciphertext

    new_text = ""
    matrix = [[" " for _ in range(n)] for _ in range(num_rails)]
    i = 0
    j = 0
    k = 2 * num_rails - 2
    l = 0
    c = 0
    for x in range(n):
        matrix[i][j] = ciphertext[x]
        if k == 2 * num_rails - 2:
            j += k
        elif k == 0:
            j += l
        else:
            if c % 2 == 0:
                j += k
            else:
                j += l
            c += 1
        if j > n - 1:
            i += 1
            j = i
            k -= 2
            l += 2
            c = 0
    for i in matrix:
        print(i)
    for j in range(n):
        for i in range(num_rails):
            if matrix[i][j] != " ":
                new_text = new_text + matrix[i][j]
    return new_text


c_encrypted = encrypt_caesar("PYTHON:)xyz")
print(c_encrypted)
c_decrypted = decrypt_caesar("SBWKRQ:)abc")
print(c_decrypted)
v_encrypted = encrypt_vigenere("ATTACKATDAWN", "LEMON")
print(v_encrypted)
v_decrypted = decrypt_vigenere("LXFOPVEFRNHR", "LEMON")
print(v_decrypted)
s_encrypted = encrypt_scytale("IAMHURTVERYBADLYHELP", 20)
print(s_encrypted)
s_decrypted = decrypt_scytale("IMUTEYALHLAHRVRBDYEP", 2)
print(s_decrypted)
r_encrypted = encrypt_railfence("WEAREDISCOVEREDFLEEATONCE", 25)
print(r_encrypted)
r_decrypted = decrypt_railfence("WVTEOEAOACRENRSEECEIDLEDF", 6)
print(r_decrypted)
