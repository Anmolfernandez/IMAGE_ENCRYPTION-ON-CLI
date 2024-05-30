import os
import click
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from base64 import urlsafe_b64encode, urlsafe_b64decode
from getpass import getpass

# Constants
SALT_SIZE = 16
KEY_SIZE = 32
ITERATIONS = 100000
BLOCK_SIZE = 128

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a key from the password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_image(image_path: str, password: str, output_path: str):
    """Encrypt the image at the given path with the provided password."""
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)
    iv = os.urandom(algorithms.AES.block_size // 8)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(image_path, 'rb') as f:
        image_data = f.read()

    padder = padding.PKCS7(BLOCK_SIZE).padder()
    padded_data = padder.update(image_data) + padder.finalize()

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    with open(output_path, 'wb') as f:
        f.write(salt + iv + encrypted_data)

def decrypt_image(encrypted_path: str, password: str, output_path: str):
    """Decrypt the image at the given path with the provided password."""
    with open(encrypted_path, 'rb') as f:
        encrypted_data = f.read()

    salt = encrypted_data[:SALT_SIZE]
    iv = encrypted_data[SALT_SIZE:SALT_SIZE + algorithms.AES.block_size // 8]
    ciphertext = encrypted_data[SALT_SIZE + algorithms.AES.block_size // 8:]

    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(BLOCK_SIZE).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    with open(output_path, 'wb') as f:
        f.write(decrypted_data)

@click.group()
def cli():
    pass

@cli.command()
@click.argument('image_path')
@click.argument('output_path')
def encrypt(image_path, output_path):
    """Encrypt an image."""
    password = getpass(prompt='Password: ')
    encrypt_image(image_path, password, output_path)
    click.echo(f"Image encrypted and saved to {output_path}")

@cli.command()
@click.argument('encrypted_path')
@click.argument('output_path')
def decrypt(encrypted_path, output_path):
    """Decrypt an image."""
    password = getpass(prompt='Password: ')
    decrypt_image(encrypted_path, password, output_path)
    click.echo(f"Image decrypted and saved to {output_path}")

if __name__ == '__main__':
    cli()
