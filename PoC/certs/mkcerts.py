import datetime
import ipaddress
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

OUT = os.path.dirname(os.path.abspath(__file__))
HOSTS = [
    "vntool.vn",
    "bypass.vntools.net",
    "mtk.unlocktool.net",
    "ut-data.vntool.net",
    "ut-data.vntool.vn",
    "localhost",
]


def write(path, data):
    with open(path, "wb") as f:
        f.write(data)


now = datetime.datetime.now(datetime.timezone.utc)
ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ca_name = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "AR"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "UnlockTool Security Lab"),
    x509.NameAttribute(NameOID.COMMON_NAME, "UnlockTool Security Lab CA"),
])
ca_cert = (
    x509.CertificateBuilder()
    .subject_name(ca_name)
    .issuer_name(ca_name)
    .public_key(ca_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - datetime.timedelta(days=1))
    .not_valid_after(now + datetime.timedelta(days=3650))
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
    .add_extension(
        x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=False, decipher_only=False,
        ),
        critical=True,
    )
    .sign(ca_key, hashes.SHA256())
)

srv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
srv_name = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "AR"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "UnlockTool Security Lab"),
    x509.NameAttribute(NameOID.COMMON_NAME, "bypass.vntools.net"),
])
san = [x509.DNSName(h) for h in HOSTS]
san.append(x509.IPAddress(ipaddress.ip_address("127.0.0.1")))
srv_cert = (
    x509.CertificateBuilder()
    .subject_name(srv_name)
    .issuer_name(ca_name)
    .public_key(srv_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - datetime.timedelta(days=1))
    .not_valid_after(now + datetime.timedelta(days=825))
    .add_extension(x509.SubjectAlternativeName(san), critical=False)
    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
    .add_extension(x509.SubjectKeyIdentifier.from_public_key(srv_key.public_key()), critical=False)
    .add_extension(
        x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=True,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False,
        ),
        critical=True,
    )
    .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    .sign(ca_key, hashes.SHA256())
)

write(os.path.join(OUT, "ca_key.pem"), ca_key.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
    serialization.NoEncryption()))
write(os.path.join(OUT, "ca_cert.pem"), ca_cert.public_bytes(serialization.Encoding.PEM))
write(os.path.join(OUT, "ca_cert.der"), ca_cert.public_bytes(serialization.Encoding.DER))
write(os.path.join(OUT, "server_key.pem"), srv_key.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
    serialization.NoEncryption()))
with open(os.path.join(OUT, "server_chain.pem"), "wb") as f:
    f.write(srv_cert.public_bytes(serialization.Encoding.PEM))
    f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

print("CA:", os.path.join(OUT, "ca_cert.pem"))
print("chain:", os.path.join(OUT, "server_chain.pem"))
print("key:", os.path.join(OUT, "server_key.pem"))

