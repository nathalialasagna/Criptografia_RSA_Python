from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from hashlib import sha256

# Entrada da senha
senha_encrypt = str(input("Senha:")).strip()

# Verificando se a senha  está correta
while sha256(
        senha_encrypt.encode()).hexdigest() != 'f4610aa514477222afac2b77f971d069780ca2846f375849f3dfa3c0047ebbd1':  # batata
    print("Senha incorreta, tente novamente!")
    senha_encrypt = str(input("Senha:")).strip()

# Verificando o que o usuário deseja fazer
op = int(input('''O que deseja fazer?
[1]Criptogragar
[2]Descriptografar
Opção:'''))
while op != 1 or op != 2:
    print('Opção inválida, tente novamente!')
    op = int(input('''O que deseja fazer?
    [1]Criptogragar
    [2]Descriptografar
    Opção:'''))

# Se o usuário deseja criptografar
if op == 1:

    # Entrada do arquivo da chave
    chave = str(input("Nome do arquivo da chave publica:"))

    # Verificando chave
    if chave == "public_key.pem":

        # Lendo o arquivo da chave
        with open(chave, 'rb') as pem_in:
            pemlines2 = pem_in.read()
            public_key = load_pem_public_key(pemlines2, default_backend())

        # Entrada do texto
        mensagem = str(input("escreva uma mensagem:"))
        bytes_mensagem = mensagem.encode('utf-8')

        # Criptografando texto
        texto_cifrado = public_key.encrypt(
            bytes_mensagem,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        )
        print(texto_cifrado)

        # Escrevendo a mensagem a ser criptografa em um arquivo
        with open('texto_c.txt.encrypted', 'wb') as f:
            f.write(texto_cifrado)
    else:
        print("Chave publica inválida!")


# Se o usuário deseja descriptografar
elif op == 2:

    # Entrada do arquivo chave
    chave = str(input("Nome do arquivo da chave Privada:"))

    # Verificando chave
    if chave == "private_key.pem":

        # Lendo a chave
        with open(chave, 'rb') as pem_in:
            pemlines = pem_in.read()
            private_key = load_pem_private_key(pemlines, None, default_backend())

       # Entrada do arquivo criptografado
        arquivo = str(input('Nome do arquivo:'))

        # Lendo o arquivo criptografado
        with open(arquivo, 'rb') as f:
            data = f.read()

        # Descriptografando mensagem
        texto_descriptografado = private_key.decrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        )

        texto_decodificado = texto_descriptografado.decode('utf-8')

        # Saída do texto descriptografado
        print(texto_decodificado)

    else:
        print('Chave privada inválida!')

else:
    print('Opção inválida!')
