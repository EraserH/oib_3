"""Вариант 4: 3DES, длина ключа 64, 128, 192 бит - предусмотреть пользовательский выбор длины ключа
Вариант  v  предлагается выбрать как  v=rem(i,9) , где  i  - порядковый номер студента в списке.

Грубо говоря, варианты (в основном) отличаются вызовом определенного метода библиотеки и длиной ключа,
 который необходимо сгенерировать.
"""
import json
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import padding as pd
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding

key_size = 8

way_to_cipher = "wtc.txt"
public_key_way = "okw.txt"
private_key_way = "ckw.txt"

def generate_asym():
    asymmetric_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = asymmetric_key.public_key()

    # сериализация открытого ключа в файл
    with open(public_key_way, 'wb') as public_out:
        public_out.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                 format=serialization.PublicFormat.SubjectPublicKeyInfo))

    # сериализация закрытого ключа в файл
    with open(private_key_way, 'wb') as private_out:
        private_out.write(asymmetric_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                    encryption_algorithm=serialization.NoEncryption()))

    return public_key


def cypher_sym(public_key):
    symmetric_key = os.urandom(key_size)
    cyphered_key = public_key.encrypt(symmetric_key,
                                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),
                                             label=None))

    with open(way_to_cipher, 'wb') as key_file:
        key_file.write(cyphered_key)


default_file = "D:/testtext.txt"
encrypted_file = "D:/c_testtext.txt"


def decypher_key():
    with open(private_key_way, "rb") as f:
        private_bytes = f.read()

    with open(way_to_cipher, "rb") as f:
        c_key = f.read()

    private_key = load_pem_private_key(private_bytes, password=None, )

    dc_key = private_key.decrypt(c_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                           algorithm=hashes.SHA256(), label=None))

    print("Decyphered key!")
    return dc_key


def cypher_text():
    with open(default_file, "rb") as f:
        text = f.read()

    padder = pd.ANSIX923(64).padder()
    padded_text = padder.update(text) + padder.finalize()

    iv = os.urandom(key_size)  # случайное значение для инициализации блочного режима, должно быть размером с блок и каждый раз новым
    cipher = Cipher(algorithms.TripleDES(decypher_key()), modes.CBC(iv))
    encryptor = cipher.encryptor()
    c_text = encryptor.update(padded_text) + encryptor.finalize()

    with open(encrypted_file, 'wb') as c_file:
        c_file.write(c_text)

    print("ЖЕСТКО ЗАШИФРОВАЛ ПОЛНЫЙ ФАЙЛ ТЕКСТА")

    return iv


decrypted_file = "D:/dc_testtext.txt"


def decypher_text(iv):
    with open(encrypted_file, "rb") as f:
        c_text = f.read()
    cipher = Cipher(algorithms.TripleDES(decypher_key()), modes.CBC(iv))
    decryptor = cipher.decryptor()
    dc_text = decryptor.update(c_text) + decryptor.finalize()

    unpadder = pd.ANSIX923(64).unpadder()
    unpadded_dc_text = unpadder.update(dc_text) + unpadder.finalize()

    print("ЖЁСТКО НАРАСШИФРОВЫВАЛ ПОЛНЫЙ ФАЙЛ ТЕКСТА")
    print()

    print(dc_text.decode('UTF-8'))
    print(unpadded_dc_text.decode('UTF-8'))

    with open(decrypted_file, "w") as f:
        f.write(unpadded_dc_text.decode('UTF-8'))


key = generate_asym()
cypher_sym(key)
decypher_key()
iv = cypher_text()
print()
print("Вот они, слева направо:")
print()
decypher_text(iv)
print()
print("END")
