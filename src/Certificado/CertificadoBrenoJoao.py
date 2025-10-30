import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta

def gerar_certificado_breno_joao():
    # Caminho da raiz do projeto (um nível acima da pasta atual)
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

    # Caminhos para os arquivos da CA (agora estão na raiz do projeto)
    ca_cert_path = os.path.join(root_dir, "certificado_Raiz.pem")
    ca_key_path = os.path.join(root_dir, "private_key_Certificado-Raiz.pem")

    # Carregar chave privada da CA
    with open(ca_key_path, "rb") as f:
        ca_private_key = serialization.load_pem_private_key(
            f.read(), password=None, backend=default_backend()
        )

    # Carregar certificado da CA
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

    # Gerar chave privada para o certificado Breno & João
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Salvar chave privada na raiz do projeto
    private_key_path = os.path.join(root_dir, "private_key_BrenoJoao.pem")
    with open(private_key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Criar CSR (Certificate Signing Request)
    subject = x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, u"BR"),
        x509.NameAttribute(x509.oid.NameOID.STATE_OR_PROVINCE_NAME, u"PR"),
        x509.NameAttribute(x509.oid.NameOID.LOCALITY_NAME, u"Cascavel"),
        x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, u"Breno & João"),
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, u"brenojoao.ifpr.edu.br"),
    ])

    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(
        private_key, hashes.SHA256(), default_backend()
    )

    # Criar o certificado assinado pela CA
    cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .sign(ca_private_key, hashes.SHA256(), default_backend())
    )

    # Salvar o certificado Breno & João na raiz do projeto
    cert_path = os.path.join(root_dir, "certificado_Breno&Joao.pem")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print("Certificado Breno & João gerado e assinado pela CA com sucesso!")

if __name__ == "__main__":
    gerar_certificado_breno_joao()
