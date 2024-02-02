"""
Encrypted chat server using Diffie-Hellman key exchange and AES encryption.
File: server.py
Author: Stijn van der Made
Studentnummer: 500908262
Date: 02/02/2024
GitHub: https://github.com/StijnvdMade/Encrypted-Chat.git
Applied Cryptography 2023-2024
"""
import socket
import hashlib
from Crypto.Cipher import AES
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509

def load_certificate(cert_file):
    with open(cert_file, 'rb') as f:
        cert_data = f.read()
    return x509.load_pem_x509_certificate(cert_data, default_backend())

def generate_diffie_hellman_key(p, g, private_key):
    return (g ** private_key) % p

def encrypt_message(message, shared_secret):
    cipher = AES.new(shared_secret, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return nonce + ciphertext + tag

def decrypt_message(encrypted_data, shared_secret):
    nonce = encrypted_data[:16]
    ciphertext = encrypted_data[16:-16]
    tag = encrypted_data[-16:]
    cipher = AES.new(shared_secret, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode()

def main():
    host = '127.0.0.1'
    port = 12345

    print("Using Diffie-Hellman key exchange")
    p = 342132027185609483707789162229  # Replace with a large prime number
    print(f"Using prime number: {p}")
    g = 52648   # Replace with a suitable generator
    print(f"Using generator: {g}")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen()

    print(f"Server listening on {host}:{port}")

    client_socket, client_address = server_socket.accept()
    print(f"Connected to {client_address}")

    client_socket.send(b"ServerHello") # Simulate TLS handshake
    print("Sent: ServerHello")
    response = client_socket.recv(1024)
    if response == b"ClientHello":
        print("Received: ClientHello")
        client_socket.send(b"ServerKeyExchange")
        print("Sent: ServerKeyExchange")
        cert = load_certificate('servercert.crt')
        cert_bytes = cert.public_bytes(encoding=serialization.Encoding.PEM)
        client_socket.send(cert_bytes)
        response = client_socket.recv(1024)
        if response == b"ClientKeyExchange":
            print("Received: ClientKeyExchange")
            client_socket.send(b"Finished")
            print("Sent: Finished")
            print("TLS handshake complete")

    private_key_server = 6324  # Replace with a random private key
    print(f"Using private key: {private_key_server}")
    public_key_server = generate_diffie_hellman_key(p, g, private_key_server)

    client_socket.send(str(public_key_server).encode())
    client_public_key = int(client_socket.recv(1024).decode())

    shared_secret = str(pow(client_public_key, private_key_server, p)).encode()
    shared_secret = hashlib.sha256(shared_secret).digest()
    print("Using AES for encryption")

    while True:
        encrypted_data = client_socket.recv(1024)
        if not encrypted_data:
            break

        decrypted_message = decrypt_message(encrypted_data, shared_secret)
        print(f"Received: {decrypted_message}")

        response = decrypted_message.upper()
        encrypted_response = encrypt_message(response, shared_secret)
        client_socket.send(encrypted_response)

    client_socket.close()
    server_socket.close()

if __name__ == "__main__":
    main()