from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# 生成 P-256 曲线的 ECC 密钥对
private_key = ec.generate_private_key(ec.SECP256R1())  # SECP256R1 是 P-256 曲线的标准名称

# 获取公钥
public_key = private_key.public_key()

# 序列化私钥和公钥为 PEM 格式
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# 打印私钥和公钥的 PEM 格式
print("Private Key (PEM format):")
print(private_pem.decode('utf-8'))

print("\nPublic Key (PEM format):")
print(public_pem.decode('utf-8'))
