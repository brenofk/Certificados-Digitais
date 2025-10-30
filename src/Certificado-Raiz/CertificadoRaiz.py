# src/Certificado_Raiz/CertificadoRaiz.py
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509 import Name, CertificateBuilder, SubjectAlternativeName
import cryptography.x509 as x509
from datetime import datetime, timedelta

def gerar_certificado_raiz():
    # Gerar chave privada da CA
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Salvar chave privada
    with open("private_key_Certificado-Raiz.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Criar certificado autoassinado
    subject = x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, u"BR"),
        x509.NameAttribute(x509.oid.NameOID.STATE_OR_PROVINCE_NAME, u"PR"),
        x509.NameAttribute(x509.oid.NameOID.LOCALITY_NAME, u"Cascavel"),
        x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, u"IFPR"),
        x509.NameAttribute(x509.oid.NameOID.EMAIL_ADDRESS, u"ifpr.cascavel@ifpr.edu.br"),
        x509.NameAttribute(x509.oid.NameOID.BUSINESS_CATEGORY, u"Educacao"),
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, u"ifpr.edu.br"),
    ])

    certificate = (
        CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365*2))
        .add_extension(
            SubjectAlternativeName([x509.DNSName(u"alternativo.ifpr.edu.br")]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256(), default_backend())
    )

    with open("certificado_Raiz.pem", "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))

    print("✅ Certificado Raiz e chave privada gerados com sucesso!")

if __name__ == "__main__":
    gerar_certificado_raiz()
