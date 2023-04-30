cmake_minimum_required(VERSION 3.10)
# set(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -Wall -Wextra")

# Set project
project(OpenSSLEngine)

# Set the name of your engine
set(ENGINE_NAME mbengine)

# Set the version number of your engine
set(ENGINE_VERSION 1.0.0)

# Set the source files for your engine
set(ENGINE_SRCS  
  engine/mb_pkcs11_engine.c 
)

include(GoogleTest)


# Set the name of the test
set(TEST_NAME pkcs11test)

message("Source directory: ${CMAKE_CURRENT_SOURCE_DIR}")

set(OPENSSL_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/deps/openssl-1.1.1g/include")
set(OPENSSL_CRYPTO_LIBRARY "${CMAKE_CURRENT_SOURCE_DIR}/deps/openssl-1.1.1g/libcrypto.so.1.1")
set(OPENSSL_SSL_LIBRARY "${CMAKE_CURRENT_SOURCE_DIR}/deps/openssl-1.1.1g/libssl.so")

message("OpenSSL_INCLUDE_DIRS: ${OPENSSL_INCLUDE_DIR}")
message("OpenSSL_CRYPTO_LIB: ${OPENSSL_CRYPTO_LIBRARY}")
message("OpenSSL_SSL_LIB: ${OPENSSL_SSL_LIBRARY}")

set(ENGINE_IMPL_FACTORY engine_impl)
set(ENGINE_IMPL_SRC engine_impl/src)

# add impl tests
add_executable(loader_test 
  engine_impl/src/asym/sw_cert.hpp
  engine_impl/src/asym/sw_cert.cpp 
  engine_impl/src/asym/sw_pkey.hpp
  engine_impl/src/asym/sw_pkey.cpp
  engine_impl/src/asym/sw_pubkey.hpp
  engine_impl/src/asym/sw_pubkey.cpp
  engine_impl/unit_tests/test_sw_loaders.cpp)

target_link_libraries(
  loader_test
  GTest::gtest_main
  ${OPENSSL_CRYPTO_LIBRARY} 
  ${OPENSSL_SSL_LIBRARY}
)

target_include_directories(
  loader_test PRIVATE 
    ${OPENSSL_INCLUDE_DIR}
    ${ENGINE_IMPL_FACTORY}
    ${ENGINE_IMPL_SRC}
    )


# add impl tests
add_executable(digest_test 
  engine_impl/src/digests/sw_digest_sha256.hpp
  engine_impl/src/digests/sw_digest_sha256.cpp 
  engine_impl/src/digests/sw_digest_sha384.hpp
  engine_impl/src/digests/sw_digest_sha384.cpp 
  engine_impl/unit_tests/test_sw_digests.cpp
  )

target_link_libraries(
  digest_test
  GTest::gtest_main
  ${OPENSSL_CRYPTO_LIBRARY} 
  ${OPENSSL_SSL_LIBRARY}
)

target_include_directories(
  digest_test PRIVATE 
    ${OPENSSL_INCLUDE_DIR}
    ${ENGINE_IMPL_FACTORY}
    ${ENGINE_IMPL_SRC}
    )

# add impl tests
add_executable(ec_test 
  engine_impl/src/asym/sw_ec.hpp
  engine_impl/src/asym/sw_ec.cpp
  engine_impl/src/digests/sw_digest_sha256.cpp
  engine_impl/src/digests/sw_digest_sha384.cpp
  engine_impl/unit_tests/test_sw_ec.cpp
  )

target_link_libraries(
  ec_test
  GTest::gtest_main
  ${OPENSSL_CRYPTO_LIBRARY} 
  ${OPENSSL_SSL_LIBRARY}
)

target_include_directories(
  ec_test PRIVATE 
    ${OPENSSL_INCLUDE_DIR}
    ${ENGINE_IMPL_FACTORY}
    ${ENGINE_IMPL_SRC}
    )


# add impl tests
add_executable(cipher_test 
  engine_impl/src/ciphers/sw_cipher_aes256cbc.hpp  
  engine_impl/src/ciphers/sw_cipher_aes256cbc.cpp  
  engine_impl/src/ciphers/sw_cipher_aes256gcm.hpp  
  engine_impl/src/ciphers/sw_cipher_aes256gcm.cpp  
  engine_impl/src/ciphers/sw_cipher_chacha20.hpp  
  engine_impl/src/ciphers/sw_cipher_chacha20.cpp  
  engine_impl/unit_tests/test_sw_ciphers.cpp
  )

target_link_libraries(
  cipher_test
  GTest::gtest_main
  ${OPENSSL_CRYPTO_LIBRARY} 
  ${OPENSSL_SSL_LIBRARY}
)

target_include_directories(
  cipher_test PRIVATE 
    ${OPENSSL_INCLUDE_DIR}
    ${ENGINE_IMPL_FACTORY}
    ${ENGINE_IMPL_SRC}
    )


# set(CURL_LIBRARY "${CMAKE_CURRENT_SOURCE_DIR}/deps/curl-7.78.0/lib/.libs/libcurl.so")
# set(CURL_INCLUDE "${CMAKE_CURRENT_SOURCE_DIR}/deps/curl-7.78.0/include")

# add_executable(curl_test curl_test.cpp)
# target_link_libraries(
#   curl_test
#   GTest::gtest_main
#   ${CURL_LIBRARY}
#   ${OPENSSL_CRYPTO_LIBRARY} 
#   ${OPENSSL_SSL_LIBRARY}
#   ${ENGINE_NAME}  
# )
# target_include_directories(
#   curl_test PRIVATE
#   ${CURL_INCLUDE} 
#   ${OPENSSL_INCLUDE_DIR}
# )


# Create a shared library for engine implementation
set(ENGINE_IMPL_NAME mbengineimpl)

# Set the source files for your engine
set(ENGINE_IMPL_SRCS 
  # mapping functions
  engine_impl/engine_link.cpp 
  engine_impl/engine_link_digests.cpp 
  engine_impl/engine_link_sym_ciphers.cpp 
  engine_impl/engine_link_pkey.cpp
  engine_impl/engine_link_ecdsa.cpp
  engine_impl/engine_link_random.cpp

  # instances
  engine_impl/src/engine_factory.cpp
  engine_impl/src/digests/sw_digest_sha256.cpp
  engine_impl/src/digests/sw_digest_sha384.cpp
  engine_impl/src/ciphers/sw_cipher_aes256cbc.cpp
  engine_impl/src/ciphers/sw_cipher_aes256gcm.cpp
  engine_impl/src/ciphers/sw_cipher_chacha20.cpp
)

add_library(
  ${ENGINE_IMPL_NAME} SHARED ${ENGINE_IMPL_SRCS})

target_include_directories(
  ${ENGINE_IMPL_NAME} PRIVATE ${OPENSSL_INCLUDE_DIR}
  ${ENGINE_IMPL_FACTORY}
  )
target_link_libraries(${ENGINE_IMPL_NAME} PRIVATE ${OPENSSL_CRYPTO_LIBRARY} ${OPENSSL_SSL_LIBRARY})
target_compile_options(${ENGINE_IMPL_NAME} PUBLIC -Wunused-parameter)


# Create a shared library for your engine
add_library(${ENGINE_NAME} SHARED ${ENGINE_SRCS})

# Surpress warnings
target_compile_options(${ENGINE_NAME} PUBLIC -Wdeprecated-declarations -Wimplicit-function-declaration)

# Set the version number of your engine
set_target_properties(${ENGINE_NAME} PROPERTIES VERSION ${ENGINE_VERSION})

# Link against OpenSSL
target_include_directories(${ENGINE_NAME} PRIVATE ${OPENSSL_INCLUDE_DIR} ${OPENSSL_CRYPTO_INCLUDE_DIR} engine_impl)
target_link_libraries(${ENGINE_NAME} PRIVATE ${OPENSSL_CRYPTO_LIBRARY} ${OPENSSL_SSL_LIBRARY} ${ENGINE_IMPL_NAME})

# openssl tests

include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

enable_testing()

add_executable(engine_test test.cpp)
target_link_libraries(
    engine_test
    GTest::gtest_main
    ${ENGINE_NAME} 
    ${ENGINE_IMPL_NAME} 
    ${OPENSSL_CRYPTO_LIBRARY} 
    ${OPENSSL_SSL_LIBRARY}
)
target_include_directories(
    engine_test PRIVATE 
    ${CURL_INCLUDE} 
    ${OPENSSL_INCLUDE_DIR})

gtest_discover_tests(engine_test)
# gtest_discover_tests(curl_test)