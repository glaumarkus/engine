cmake_minimum_required(VERSION 3.10)
set(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -Wall -Wextra")

# Set project
project(OpenSSLEngine)

# Set the name of your engine
set(ENGINE_NAME mbengine)

# Set the version number of your engine
set(ENGINE_VERSION 1.0.0)

# Set the source files for your engine
set(ENGINE_SRCS mb_pkcs11_engine.c)

# Set the name of the test
set(TEST_NAME pkcs11test)

# Set the include directories for OpenSSL
# find_package(OpenSSL REQUIRED)

set(OPENSSL_INCLUDE_DIR "/usr/local/include")
set(OPENSSL_CRYPTO_LIBRARY "/home/glaum/openssl/libcrypto.so")
set(OPENSSL_SSL_LIBRARY "/home/glaum/openssl/libssl.so")

message("OpenSSL_INCLUDE_DIRS: ${OPENSSL_INCLUDE_DIR}")
message("OpenSSL_CRYPTO_LIB: ${OPENSSL_CRYPTO_LIBRARY}")
message("OpenSSL_SSL_LIB: ${OPENSSL_SSL_LIBRARY}")

# Create a shared library for your engine
add_library(${ENGINE_NAME} SHARED ${ENGINE_SRCS})
target_include_directories(${ENGINE_NAME} PRIVATE )

# Surpress warnings
target_compile_options(${ENGINE_NAME} PUBLIC -Wdeprecated-declarations -Wimplicit-function-declaration)

# Set the version number of your engine
set_target_properties(${ENGINE_NAME} PROPERTIES VERSION ${ENGINE_VERSION})

# Link against OpenSSL
target_include_directories(${ENGINE_NAME} PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(${ENGINE_NAME} PRIVATE ${OPENSSL_CRYPTO_LIBRARY} ${OPENSSL_SSL_LIBRARY})

# Create the test file
add_executable(${TEST_NAME} pkcs11_engine_test.cpp)
target_include_directories(${TEST_NAME} PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(${TEST_NAME} PRIVATE ${ENGINE_NAME} ${OPENSSL_CRYPTO_LIBRARY} ${OPENSSL_SSL_LIBRARY})

