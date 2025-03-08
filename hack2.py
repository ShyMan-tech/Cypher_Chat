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
        mgf=padding.MGF1(algorith=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        Label=None
        )
    )
    
    return decrypted.decode()

message='hello world'
encrypted_msg=encrypt_message(message,
                              public_key)
print('Encrypted: ', encrypted_msg)

decrypted_msg=decrypt_message(encrypted_msg,private_key)
print('decrypted: ', decrypted_msg)


# 14, 38
# File "/home/iastudent/Cypher_Chat/main.py", line 14, in encrypt_message
#    padding.OAEP(
#  File "/home/iastudent/Cypher_Chat/main.py", line 38, in <module>
#    encrypted_msg=encrypt_message(message,
#TypeError: OAEP.__init__() got an unexpected keyword argument 'mfg'