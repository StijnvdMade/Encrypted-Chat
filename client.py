"""
Encrypted chat client using Diffie-Hellman key exchange and AES encryption.
File: client.py
Author: Stijn van der Made
Studentnummer: 500908262
Date: 02/02/2024
GitHub: https://github.com/StijnvdMade/Encrypted-Chat.git
Applied Cryptography 2023-2024
"""
import socket
import hashlib
from Crypto.Cipher import AES
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.hazmat.primitives import serialization

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

    print(f"Connecting to server on {host}:{port}")
    print("Using Diffie-Hellman key exchange")
    p = 342132027185609483707789162229  # Replace with the same prime number used in server.py
    print(f"Using prime number: {p}")
    g = 52648   # Replace with the same generator used in server.py
    print(f"Using generator: {g}")

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))

    response = client_socket.recv(1024)
    if response == b"ServerHello":
        print("Received: ServerHello")
        client_socket.send(b"ClientHello")
        print("Sent: ClientHello")
        response = client_socket.recv(1024)
        if response == b"ServerKeyExchange":
            print("Received: ServerKeyExchange")
            cert_bytes = client_socket.recv(2048)
            cert = load_certificate('servercert.crt')
            cert_bytes_2 = cert.public_bytes(encoding=serialization.Encoding.PEM)
            if cert_bytes == cert_bytes_2:
                print("Received server certificate")
                client_socket.send(b"ClientKeyExchange")
                print("Sent: ClientKeyExchange")
                response = client_socket.recv(1024)
                if response == b"Finished":
                    print("Received: Finished")
                    print("TLS handshake completed successfully")
            else:
                print("Server certificate verification failed")
                client_socket.close()
                return

    private_key_client = 1555  # Replace with a different random private key
    print(f"Using private key: {private_key_client}")
    public_key_client = generate_diffie_hellman_key(p, g, private_key_client)

    server_public_key = int(client_socket.recv(1024).decode())
    client_socket.send(str(public_key_client).encode())

    shared_secret = str(pow(server_public_key, private_key_client, p)).encode()
    shared_secret = hashlib.sha256(shared_secret).digest()

    print("Using AES for encryption")

    while True:
        message = input("Enter message: ")
        if message == "exit":
            print("Exiting...")
            client_socket.close()
            break

        encrypted_message = encrypt_message(message, shared_secret)
        client_socket.send(encrypted_message)

        response = client_socket.recv(1024)
        decrypted_response = decrypt_message(response, shared_secret)
        print(f"Received: {decrypted_response}")

if __name__ == "__main__":
    main()