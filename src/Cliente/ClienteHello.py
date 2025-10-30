# src/Cliente/ClienteHello.py
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64

def hello():
    print(" Hello servidor")

    cert_path = "certificado_Breno&Joao.pem"
    message = b"Professor voce ja fez a chamada?"

    # Carregar certificado e extrair chave pública
    with open(cert_path, "rb") as cert_file:
        cert = x509.load_pem_x509_certificate(cert_file.read(), default_backend())
        public_key = cert.public_key()

    # Cifrar mensagem
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    cipher_b64 = base64.b64encode(ciphertext).decode("utf-8")

    with open("desafioMensagemCifrada.txt", "w") as f:
        f.write(cipher_b64)

    print(" Mensagem cifrada salva como 'desafioMensagemCifrada.txt'")

if __name__ == "__main__":
    hello()
