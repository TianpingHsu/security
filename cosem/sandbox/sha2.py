import hashlib

# 要计算哈希值的字符串
data = "Hello World"

# 计算 SHA-256 哈希值
sha256_hash = hashlib.sha256(data.encode()).digest()  # 使用 digest() 获取字节形式的哈希值

# 将每个字节以 16 进制形式打印，带有前缀 0x，并用逗号分隔
hex_bytes = [f"0x{byte:02x}" for byte in sha256_hash]
print(f"SHA-256 hash of '{data}' (each byte in hex):")
print(",".join(hex_bytes))


# 计算 SHA-256 哈希值
sha384_hash = hashlib.sha384(data.encode()).digest()  # 使用 digest() 获取字节形式的哈希值

# 将每个字节以 16 进制形式打印，带有前缀 0x，并用逗号分隔
hex_bytes = [f"0x{byte:02x}" for byte in sha384_hash]
print(f"SHA-256 hash of '{data}' (each byte in hex):")
print(",".join(hex_bytes))


