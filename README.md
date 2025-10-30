```text
🟡 Cliente                               🔵 Servidor
   |            Início da comunicação          |
   |                                           |
   |-------- Hello! --------------------->>    | ①
   |   <<------------- Cert_SVR -----------    | ②
   |----- Enc(RSA, Pub_SVR, desafio) ---->>    | ③
   |   <<-------------------- desafio ---------| ④
   |----- Autentica o desafio --------------->>| ⑤
   |                                           |
   |             Fim da comunicação            |


### 1️⃣ Gerar o Certificado Raiz (CA)
cd src/Certificado_Raiz  
python CertificadoRaiz.py

---

### 2️⃣ Gerar o Certificado Breno & João
cd ../Certificado  
python CertificadoBrenoJoao.py

---

### 3️⃣ Executar o Cliente (Gerar Mensagem Cifrada)
cd ../Cliente  
python ClienteHello.py

---

### 4️⃣ Executar o Servidor (Decifrar Mensagem)
cd ../Servidor  
python ServidorDecifrar.py

---

### 5️⃣ Verificar a Mensagem Decifrada
cat mensagemDesafioDecifrado.txt

