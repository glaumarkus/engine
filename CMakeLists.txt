cmake_minimum_required(VERSION 3.10)
set(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -Wall -Wextra")

# Set project
project(OpenSSLEngine)

# Set the name of your engine
set(ENGINE_NAME mbengine)

# Set the version number of your engine
set(ENGINE_VERSION 1.0.0)

# Set the source files for your engine
set(ENGINE_SRCS 
#  mb_pkcs11_engine_sha256.c  
  mb_pkcs11_engine.c 
)

# Set the name of the test
set(TEST_NAME pkcs11test)

# Set the include directories for OpenSSL
# find_package(OpenSSL REQUIRED)

set(OPENSSL_INCLUDE_DIR "/home/glaum/curl/openssl-1.1.1b/include")
set(OPENSSL_CRYPTO_LIBRARY "/home/glaum/curl/openssl-1.1.1b/libcrypto.so.1.1")
set(OPENSSL_SSL_LIBRARY "/home/glaum/curl/openssl-1.1.1b/libssl.so")

message("OpenSSL_INCLUDE_DIRS: ${OPENSSL_INCLUDE_DIR}")
message("OpenSSL_CRYPTO_LIB: ${OPENSSL_CRYPTO_LIBRARY}")
message("OpenSSL_SSL_LIB: ${OPENSSL_SSL_LIBRARY}")


# Create a shared library for engine implementation
set(ENGINE_IMPL_NAME mbengineimpl)

# Set the source files for your engine
set(ENGINE_IMPL_SRCS 
  engine_link.cpp 
  engine_link_digests.cpp 
  engine_link_sym_ciphers.cpp 
  engine_link_pkey.cpp
  engine_link_ecdsa_copy.cpp
)

add_library(${ENGINE_IMPL_NAME} SHARED ${ENGINE_IMPL_SRCS})
target_include_directories(${ENGINE_IMPL_NAME} PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(${ENGINE_IMPL_NAME} PRIVATE ${OPENSSL_CRYPTO_LIBRARY} ${OPENSSL_SSL_LIBRARY})
target_compile_options(${ENGINE_IMPL_NAME} PUBLIC -Wunused-parameter)




# Create a shared library for your engine
add_library(${ENGINE_NAME} SHARED ${ENGINE_SRCS})

# Surpress warnings
target_compile_options(${ENGINE_NAME} PUBLIC -Wdeprecated-declarations -Wimplicit-function-declaration)

# Set the version number of your engine
set_target_properties(${ENGINE_NAME} PROPERTIES VERSION ${ENGINE_VERSION})

# Link against OpenSSL
target_include_directories(${ENGINE_NAME} PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(${ENGINE_NAME} PRIVATE ${OPENSSL_CRYPTO_LIBRARY} ${OPENSSL_SSL_LIBRARY} ${ENGINE_IMPL_NAME})


set(CURL_LIBRARY "/home/glaum/curl/curl-7.68.0/lib/.libs/libcurl.so")
set(CURL_INCLUDE "/home/glaum/curl/curl-7.68.0/include")
message("CURL_INCLUDE_DIRS: ${CURL_INCLUDE}")

add_executable(${TEST_NAME} curl_example.cpp)
target_link_libraries(${TEST_NAME} ${CURL_LIBRARY} ${ENGINE_NAME} ${ENGINE_IMPL_NAME} ${OPENSSL_CRYPTO_LIBRARY} ${OPENSSL_SSL_LIBRARY})
target_include_directories(${TEST_NAME} PRIVATE ${CURL_INCLUDE} ${OPENSSL_INCLUDE_DIR})

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


include(GoogleTest)
gtest_discover_tests(engine_test)