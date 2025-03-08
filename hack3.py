from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

private_key=rsa.generate_private_key(public_exponent=65537, key_size=2048
                                     )
public_key=private_key.public_key()

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def encrypt_message(message,public_key):
    encrypted=public_key.encrypt(
        message.encode(),
        padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
      )
    )
    return encrypted

def decrypt_message(encrypted_message,
                    private_key):
    decrypted=private_key.decrypt(
        encrypted_message,
        padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
        )
    )
    
    return decrypted.decode()

message='skibidii tiolet'
encrypted_msg=encrypt_message(message,
                              public_key)
print('Encrypted: ', encrypted_msg)

decrypted_msg=decrypt_message(encrypted_msg,private_key)
print('decrypted: ', decrypted_msg)

import socket
from cryptography.hazmat.primitives.asymmetric import serialization
with open('private_key.pem', 'rb') as f:
    private_key=serialization.load_pem_private_key(f.read(), password=None)

server=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('0.0.0.0',12345))
server.listen(1)

print('waiting for a sigma connection...')
conn,addr = server.accept()
print(f'connected to {addr}')
encrypted_msg=conn.rcv(4090)
decrypted_msg=decrypted_msg(encrypted_msg, private_key)
print('decrypted_msg:', decrypted_msg)
server.close

import socket
from cryptography.hazmat.primitives.asymmetric import serialization
with open('public_key.pem','rb'):
    public_key=serialization