import pytest
from crypto import (
    encrypt_caesar,
    decrypt_caesar,
    encrypt_vigenere,
    decrypt_vigenere,
    encrypt_scytale,
    decrypt_scytale,
    encrypt_railfence,
    decrypt_railfence,
)


def test_things():
    assert encrypt_caesar("PYTHON") == "SBWKRQ"
    assert decrypt_caesar("SBWKRQ") == "PYTHON"
    assert encrypt_vigenere("ATTACKATDAWN", "LEMON") == "LXFOPVEFRNHR"
    assert decrypt_vigenere("LXFOPVEFRNHR", "LEMON") == "ATTACKATDAWN"
    assert encrypt_scytale("IAMHURTVERYBADLYHELP", 5) == "IRYYATBHMVAEHEDLURLP"
    assert decrypt_scytale("IRYYATBHMVAEHEDLURLP", 5) == "IAMHURTVERYBADLYHELP"
    assert (
        encrypt_railfence("WEAREDISCOVEREDFLEEATONCE", 3) == "WECRLTEERDSOEEFEAOCAIVDEN"
    )
    assert (
        decrypt_railfence("WECRLTEERDSOEEFEAOCAIVDEN", 3) == "WEAREDISCOVEREDFLEEATONCE"
    )
