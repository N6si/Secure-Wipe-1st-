# generate_keys.py
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from pathlib import Path

Path("keys").mkdir(exist_ok=True)

priv = ec.generate_private_key(ec.SECP256R1())
priv_pem = priv.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
with open("keys/priv.pem","wb") as f:
    f.write(priv_pem)

pub = priv.public_key()
pub_pem = pub.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
with open("keys/pub.pem","wb") as f:
    f.write(pub_pem)

print("keys/priv.pem and keys/pub.pem created.")
