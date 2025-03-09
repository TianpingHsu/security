# security
openssl test code


## build
> gcc -o aes_gcm_example aes_gcm_example.c -lssl -lcrypto  


## prompt
我需要使用openssl-3.4.1实现一系列加解密，认证，加签验签的C语言接口。
它们包含以下3个套件(Security Suite)：
Security Suite Id	Security Suite name				Authenticated encryption	Digital signature	Key agreement	Hash			Key transport

0					AES-GCM-128						AES-GCM-128					not supported		not supported	not supported	AES-128 key wrap

1					ECDH-ECDSA-AES-GCM-128-SHA-256	AES-GCM-128					ECDSA with P-256	ECDH with P-256	SHA-256			AES-128 key wrap

2					ECDH-ECDSA-AES-GCM-256-SHA-384	AES-GCM-256					ECDSA with P-384	ECDH with P-384	SHA-384			AES-256 key wrap

Note:
1. 椭圆曲线使用的是NSA Suite B elliptic curves and domain parameters
2. 对于AES-GCM, ECDSA, SHA都需要支持分段运行，即可以保存上一次运行上下文，根据传入的上下文继续下一次的数据运算，直到最后一块数据
3. 对于AES-GCM，我希望可以选择仅加密(解密)，仅认证(验证)，加密且认证(解密且验证)
4. 另外请为我单独提供一个GMAC的接口实现，他的输入数据可以一次性导入并执行，不需要分段

对于Key Agreement，我们支持三种scheme:
1. the Ephemeral Unified Model C(2e, 0s, ECC CDH) scheme
2. the One-Pass Diffie-Hellman C(1e, 1s, ECC CDH) scheme
3. the Static Unified Model C(0e, 2s, ECC CDH) scheme
对于以上三种ECDH，我们使用的Key-Derivation Function是NIST的`The Single-Step KDF Specification`，你应该使用openssl中对应的实现函数；
同样的，Key-Derivation Function中使用的Hash函数也应该根据Security Suite分别使用SHA-256或者SHA-384。

代码设计与实现：我希望你分别实现AEC-GCM-128/256, SHA-256/384等接口：
注意，openssl中已经有SHA-256和SHA-384的对应接口了，例如：
```C
    unsigned char data[] = "Hello, World!";  // 待哈希的数据
    unsigned char hash[SHA256_DIGEST_LENGTH];  // 存储哈希结果
    SHA256_CTX sha256;

    // 初始化 SHA256 上下文
    SHA256_Init(&sha256);

    // 更新数据到哈希上下文
    SHA256_Update(&sha256, data, strlen((char*)data));

    // 获取最终的哈希值
    SHA256_Final(hash, &sha256);
```
你可以直接告诉我说有这些接口，并且给一个测试代码就行(请注意以上的SHA256_Update可以运行多次，如果我的data数据比较长，我能够切片）
