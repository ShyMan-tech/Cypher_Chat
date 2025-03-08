from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

private_key=rsa.generate_private_key(public_exponent=65537, key_size=2048
                                     )
public_key=private_key.public_key()

with open('private_key.pem', 'wb') as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

with open('public_key', 'wb') as f:
    f.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

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

message=input('skibidi toilet')
encrypted_msg=encrypt_message(message,public_key)

decrypted_msg=decrypt_message(encrypted_msg,private_key)
print('decrypted: ', decrypted_msg)

#loeopugofewgyoeuergfuietrrutfuertfyuertyutfuyeruqrferjrghjdfrgeroygfierwyigteritgyjrryjdftyjradsyujtryudsfryusdrgfurfgdyudfjygrkjsdfrbkhdsrfbyku
print('encrypted:', encrypted_msg)

import socket
from cryptography.hazmat.primitives import serialization
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
with open('public_key.pem','rb') as f:
    public_key=serialization.load_pem_public_key(f.read)
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect('127.0.0.1', 12345)
message=input('ENTER A MESSAGE RIGHT NOW!!! ')
encrypted_msg=encrypt_message(message,public_key)
client.send(encrypted_msg)

print(f'plain message: {message}')
print(f'encrypted: {encrypted_msg}')

client.close