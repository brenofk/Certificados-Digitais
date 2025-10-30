# src/Certificado/CertificadoBrenoJoao.py
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509 import CertificateBuilder, Name, KeyUsage
import cryptography.x509 as x509
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

def gerar_certificado_breno_joao():
    # Carrega chave privada da CA
    with open("private_key_Certificado-Raiz.pem", "rb") as f:
        ca_private_key = serialization.load_pem_private_key(f.read(), password=None)

    # Carrega certificado da CA
    with open("certificado_Raiz.pem", "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

    # Gera chave privada do novo certificado
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    with open("private_key_Breno&Joao.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Cria o certificado assinado pela CA
    subject = x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, u"BR"),
        x509.NameAttribute(x509.oid.NameOID.STATE_OR_PROVINCE_NAME, u"PR"),
        x509.NameAttribute(x509.oid.NameOID.LOCALITY_NAME, u"Cascavel"),
        x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, u"IFPR"),
        x509.NameAttribute(x509.oid.NameOID.EMAIL_ADDRESS, u"breno.soares&Joao.Guesser.edu.br"),
        x509.NameAttribute(x509.oid.NameOID.BUSINESS_CATEGORY, u"Educacao"),
        x509.NameAttribute(x509.oid.NameOID.TITLE, u"Aluno"),
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, u"Breno Soares & Joao Guesser"),
    ])

    key_usage = KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=True,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False
    )

    certificate = (
        CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(key_usage, critical=True)
        .sign(ca_private_key, hashes.SHA256(), default_backend())
    )

    with open("certificado_Breno&Joao.pem", "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))

    print("✅ Certificado Breno & Joao gerado com sucesso!")

if __name__ == "__main__":
    gerar_certificado_breno_joao()
