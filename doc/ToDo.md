To create an OpenSSL engine for mTLS (mutual TLS), you would typically need to implement the following algorithms:

    Key exchange algorithms:
    a) Diffie-Hellman (DH)
    b) Elliptic Curve Diffie-Hellman (ECDH)

    Cipher algorithms:
    a) Advanced Encryption Standard (AES)
    b) Triple Data Encryption Standard (3DES)
    c) Secure Hash Algorithm (SHA)

    Digital Signature algorithms:
    a) RSA Signature
    b) Elliptic Curve Digital Signature Algorithm (ECDSA)

    Message Authentication Code (MAC) algorithms:
    a) HMAC-SHA256
    b) HMAC-SHA384
    c) HMAC-SHA512



// PKCS11 Engine
// https://raw.githubusercontent.com/opencryptoki/openssl-ibmpkcs11/master/src/e_pkcs11.c
// includes /usr/local/include
// implement: 
// - P384
// - P256
// - ChaCha20
// - SHA384
// - AES CBC/GCM
// - Cert Verify
// // - Supported IANA strings
//         || !ENGINE_set_load_privkey_function(e, capi_load_privkey)
//         || !ENGINE_set_load_ssl_client_cert_function(e,
//                                                      capi_load_ssl_client_cert)
