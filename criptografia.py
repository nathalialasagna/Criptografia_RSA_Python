from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization import load_pem_private_key

op = int(input('''O que deseja fazer?
[1]Criptogragar
[2]Descriptografar'''))

if op == 1:
    chave = str(input("Nome do arquivo da chave publica:"))
    with open(chave, 'rb') as pem_in:
        pemlines2 = pem_in.read()
        public_key = load_pem_public_key(pemlines2, default_backend())

    #Entrada do texto
    mensagem = str(input("escreva uma mensagem:"))
    bytes_mensagem = mensagem.encode('utf-8')

    texto_cifrado = public_key.encrypt(
        bytes_mensagem,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )
    print(texto_cifrado)
    with open('textoc.txt', 'wb') as f:
        f.write(texto_cifrado)








elif op == 2:
    chave = str(input("Nome do arquivo da chave Privada:"))
    with open(chave, 'rb') as pem_in:
        pemlines = pem_in.read()
        private_key = load_pem_private_key(pemlines, None, default_backend())
    arquivo = str(input('Nome do arquivo:'))
    with open(arquivo, 'rb') as f:
       data = f.read()



    texto_descriptografado = private_key.decrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
    )   )

    texto_decodificado = texto_descriptografado.decode('utf-8')

    # Saída do texto descriptografado
    print(texto_decodificado)

