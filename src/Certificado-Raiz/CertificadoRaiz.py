import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509 import Name, CertificateBuilder, SubjectAlternativeName
import cryptography.x509 as x509
from datetime import datetime, timedelta

# Caminho de saída para a raiz do projeto
output_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# Gerar chave privada da CA
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# Salvar chave privada na raiz do projeto
private_key_path = os.path.join(output_dir, "private_key_Certificado-Raiz.pem")
with open(private_key_path, "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

# Gerar chave pública
public_key = private_key.public_key()

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

issuer = subject  # Autoassinado

# Definir validade
valid_from = datetime.utcnow()
valid_until = valid_from + timedelta(days=365 * 2)

# Criar e assinar certificado
certificate = CertificateBuilder().subject_name(
    subject
).issuer_name(
    issuer
).public_key(
    public_key
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    valid_from
).not_valid_after(
    valid_until
).add_extension(
    SubjectAlternativeName([x509.DNSName(u"alternativo.ifpr.edu.br")]),
    critical=False,
).sign(private_key, hashes.SHA256(), default_backend())

# Salvar o certificado na raiz
cert_path = os.path.join(output_dir, "certificado_Raiz.pem")
with open(cert_path, "wb") as f:
    f.write(certificate.public_bytes(serialization.Encoding.PEM))

print("Certificado Raiz e chave privada gerados com sucesso na raiz do projeto!")
print(f"- {private_key_path}")
print(f"- {cert_path}")
