import os
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

def decifrar_mensagem():
    # Caminho da raiz do projeto (pasta src)
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    private_key_path = os.path.join(root_dir, "private_key_BrenoJoao.pem")
    input_path = os.path.join(root_dir, "desafioMensagemCifrada.txt")
    output_path = os.path.join(root_dir, "mensagemDesafioDecifrado.txt")

    # Carregar chave privada
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )

    # Ler mensagem cifrada (Base64)
    with open(input_path, "r") as f:
        cipher_base64 = f.read()
    ciphertext = base64.b64decode(cipher_base64)

    # Decifrar
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # Salvar resultado
    with open(output_path, "wb") as f:
        f.write(plaintext)

    print(f"Mensagem decifrada salva em: {output_path}")

if __name__ == "__main__":
    decifrar_mensagem()
