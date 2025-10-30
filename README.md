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
   |             Fim da comunicação             |
