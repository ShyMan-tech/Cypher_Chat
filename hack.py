from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

private_key=rsa.generate_private_key(public_exponent=65537, key_size=2048
                                     )
public_key=private_key.public_key()

with open('pivate_key.pim', 'wb') as f:
    f.write(private_key.private_bytes())

print('skibidi toilet is the greatest, don"t be sigma')
print(input('Why are you gay? '))