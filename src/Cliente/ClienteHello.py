import os
import base64
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def hello():
    print("Hello servidor")

    # Caminho da raiz do projeto (pasta src)
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    cert_path = os.path.join(root_dir, "certificado_Breno&Joao.pem")

    messageDesafio = b'Professor voce ja fez a chamada?'

    # Ler o certificado
    with open(cert_path, "rb") as cert_file:
        cert_data = cert_file.read()
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())

    # Obter a chave pública do certificado
    public_key = cert.public_key()

    # Configurar o padding OAEP
    padding_config = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )

    # Cifrar a mensagem
    ciphertext = public_key.encrypt(messageDesafio, padding_config)

    # Codificar em Base64
    cipher_base64 = base64.b64encode(ciphertext).decode("utf-8")

    # Salvar o arquivo dentro da pasta src
    output_path = os.path.join(root_dir, "desafioMensagemCifrada.txt")

    with open(output_path, "w") as f:
        f.write(cipher_base64)

    print(f"Mensagem cifrada salva em: {output_path}")

if __name__ == "__main__":
    hello()
