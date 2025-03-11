cmake_minimum_required(VERSION 3.12)
project(CryptoDemo LANGUAGES CXX)

# 设置C++标准要求
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")

set(OPENSSL_ROOT_DIR /usr/local/lib64/)
# 查找OpenSSL依赖
find_package(OpenSSL REQUIRED)

# 创建安全模块库
add_library(security_lib STATIC
    security.cpp
    security.hpp
)

# 包含头文件目录
target_include_directories(security_lib PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# 链接OpenSSL到库
target_link_libraries(security_lib PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
)

# 创建测试可执行文件
add_executable(test_sha2
    test_sha2.cpp
)
target_link_libraries(test_sha2
    security_lib
)

add_executable(test_aes
    test_aes.cpp
)
target_link_libraries(test_aes
    security_lib
)

add_executable(test_keywrap
    test_keywrap.cpp
)
target_link_libraries(test_keywrap
    security_lib
)

add_executable(test_ecdsa
    test_ecdsa.cpp
)

target_link_libraries(test_ecdsa
    security_lib
)

add_executable(test_ecdh
    test_ecdh.cpp
)

target_link_libraries(test_ecdh
    security_lib
)

# 安装规则（可选）
install(TARGETS test_sha2 test_aes
    RUNTIME DESTINATION bin
)
