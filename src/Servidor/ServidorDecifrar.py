# src/Servidor/ServidorDecifrar.py
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import base64

def decifrar_mensagem():
    private_key_path = "private_key_Breno&Joao.pem"
    mensagem_cifrada_path = "desafioMensagemCifrada.txt"
    mensagem_decifrada_path = "mensagemDesafioDecifrado.txt"

    # Carregar chave privada
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    # Ler mensagem cifrada
    with open(mensagem_cifrada_path, "r") as f:
        cipher_b64 = f.read().strip()

    cipher_bytes = base64.b64decode(cipher_b64)

    # Decifrar
    plaintext = private_key.decrypt(
        cipher_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    mensagem = plaintext.decode("utf-8")

    # Salvar
    with open(mensagem_decifrada_path, "w") as f:
        f.write(mensagem)

    print("✅ Mensagem decifrada salva em 'mensagemDesafioDecifrado.txt'")

if __name__ == "__main__":
    decifrar_mensagem()
