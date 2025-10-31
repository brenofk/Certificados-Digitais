# ClienteHello.py
# Lê o certificado do servidor (certificado.pem assinado pela CA),
# verifica assinatura da CA, cifra a mensagem com a chave pública do certificado
# e salva em pem/desafioMensagemCifrada.txt (Base64).

import os
import base64
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# Mensagem a ser cifrada
MENSAGEM = b"voce pode confiar no servidor"

def find_pem_dir(root_dir):
    """Retorna o caminho da pasta pem dentro do projeto"""
    return os.path.join(root_dir, "pem")

def load_cert(path):
    """Carrega um certificado PEM"""
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read(), default_backend())

def verify_cert_signed_by_ca(server_cert, ca_cert):
    """Verifica se o certificado do servidor foi assinado pela CA"""
    ca_pub = ca_cert.public_key()
    try:
        ca_pub.verify(
            server_cert.signature,
            server_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),  # assinaturas X.509 usam PKCS#1 v1.5
            server_cert.signature_hash_algorithm,
        )
        return True
    except Exception as e:
        print("Falha ao verificar assinatura do certificado pelo CA:", e)
        return False

def main():
    # Caminho da pasta src
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    pem_dir = find_pem_dir(root_dir)

    ca_path = os.path.join(pem_dir, "certificado_Raiz.pem")
    server_cert_path = os.path.join(pem_dir, "certificado.pem")

    if not (os.path.exists(ca_path) and os.path.exists(server_cert_path)):
        print("Arquivos CA ou certificado do servidor não encontrados em:", pem_dir)
        return

    ca_cert = load_cert(ca_path)
    server_cert = load_cert(server_cert_path)
    print("Certificados carregados.")

    if not verify_cert_signed_by_ca(server_cert, ca_cert):
        print("Certificado do servidor NÃO válido.")
        return
    print("Assinatura verificada com sucesso. Usando chave pública do certificado do servidor.")

    # Obter chave pública e cifrar a mensagem
    server_pubkey = server_cert.public_key()
    ciphertext = server_pubkey.encrypt(
        MENSAGEM,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Codificar em Base64
    cipher_b64 = base64.b64encode(ciphertext).decode("utf-8")

    # Salvar o arquivo dentro da pasta pem/
    out_path = os.path.join(pem_dir, "desafioMensagemCifrada.txt")
    with open(out_path, "w") as f:
        f.write(cipher_b64)

    print("Mensagem cifrada salva em:", out_path)

if __name__ == "__main__":
    main()
