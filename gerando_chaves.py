from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

#Gerando chave privada
private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
#serializando chave privada
pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
)
#Guardando chave privada em um arquivo pem
with open("private_key.pem", 'wb') as pem_out:
        pem_out.write(pem_private)

#Gerando chave publica
public_key = private_key.public_key()

#Serealizando chave publica
pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
)
#Guardando chave publica em um arquivo pem
with open("public_key.pem", 'wb') as pem_out:
        pem_out.write(pem_public)
