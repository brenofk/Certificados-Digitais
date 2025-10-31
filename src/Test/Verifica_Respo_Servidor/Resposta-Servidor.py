# Resposta-Servidor.py
# Lê a resposta do servidor e determina se ele é autêntico

import os

def find_pem_dir(root_dir):
    """Retorna o caminho da pasta pem dentro do projeto"""
    return os.path.join(root_dir, "pem")

def main():
    # Caminho da pasta Test (um nível acima da pasta Verifica_Respo_Servidor)
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    pem_dir = find_pem_dir(root_dir)

    # Caminho completo para o arquivo de resposta
    resposta_path = os.path.join(pem_dir, "respostaServidor.txt")

    # Verifica se o arquivo existe
    if not os.path.exists(resposta_path):
        print("Arquivo de resposta do servidor não encontrado em:", resposta_path)
        return

    # Lê a resposta do servidor
    with open(resposta_path, "r", encoding="utf-8") as f:
        resposta = f.read().strip()

    print(f"Resposta recebida do servidor: {resposta}")

    # Verifica se a resposta confere com a mensagem original
    mensagem_original = "voce pode confiar no servidor"
    if resposta == mensagem_original:
        print("Autenticação bem-sucedida: o servidor é autêntico.")
    else:
        print("Falha na autenticação: o servidor NÃO é quem diz ser.")

if __name__ == "__main__":
    main()
