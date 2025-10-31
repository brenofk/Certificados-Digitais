# Servidor-Falso.py
# Lê pem/desafioMensagemCifrada.txt, tenta decifrar com uma chave privada falsa
# e grava a resposta em pem/respostaServidor.txt

import os
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

def find_pem_dir(root_dir):
    """Retorna o caminho da pasta pem dentro do projeto"""
    return os.path.join(root_dir, "pem")

def ensure_fake_private_key(path):
    """Gera e salva uma private key 'falsa' se não existir; retorna o objeto private key"""
    if os.path.exists(path):
        with open(path, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open(path, "wb") as f:
        f.write(priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    return priv

def main():
    # diretório raiz (pasta src)
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    pem_dir = find_pem_dir(root_dir)

    input_path = os.path.join(pem_dir, "desafioMensagemCifrada.txt")
    fake_key_path = os.path.join(pem_dir, "private_key_falso.pem")
    resposta_path = os.path.join(pem_dir, "respostaServidor.txt")

    if not os.path.exists(pem_dir):
        print("Pasta pem não encontrada em:", pem_dir)
        return

    if not os.path.exists(input_path):
        print("Arquivo de desafio cifrado não encontrado:", input_path)
        return

    fake_priv = ensure_fake_private_key(fake_key_path)
    print("Usando chave privada falsa em:", fake_key_path)

    # Ler ciphertext (Base64)
    try:
        with open(input_path, "r", encoding="utf-8") as f:
            b64 = f.read().strip()
        ciphertext = base64.b64decode(b64)
    except Exception as e:
        print("Erro ao ler/decodificar o arquivo cifrado:", e)
        return

    # Tenta decifrar com a chave FALSA (não corresponde ao certificado)
    try:
        plaintext = fake_priv.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        resp_text = plaintext.decode("utf-8", errors="replace")
        print("Mensagem decifrada (inesperado):", resp_text)
    except Exception as e:
        print("Falha ao decifrar (esperado para servidor falso):", repr(e))
        resp_text = "nao consegui decifrar a mensagem"

    # Grava resposta em pem/respostaServidor.txt
    try:
        with open(resposta_path, "w", encoding="utf-8") as f:
            f.write(resp_text)
        print("Resposta gravada em:", resposta_path)
    except Exception as e:
        print("Erro ao gravar resposta:", e)

if __name__ == "__main__":
    main()
