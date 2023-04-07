#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>

#ifndef ENGINE_WRAP_H
#define ENGINE_WRAP_H

// wrapper for c++
#ifdef __cplusplus
extern "C" {
#endif


/* sha256 mapping */
int sha256_init(EVP_MD_CTX *ctx);
int sha256_update(EVP_MD_CTX *ctx, const void *in, size_t len);
int sha256_final(EVP_MD_CTX *ctx, unsigned char *md);
int sha256_cleanup(EVP_MD_CTX *ctx);
size_t sha256_size();

/* sha384 mapping */
int sha384_init(EVP_MD_CTX *ctx);
int sha384_update(EVP_MD_CTX *ctx, const void *in, size_t len);
int sha384_final(EVP_MD_CTX *ctx, unsigned char *md);
int sha384_cleanup(EVP_MD_CTX *ctx);
size_t sha384_size();

// /* aes256 cbc mapping*/
// int aes256_cbc_init(EVP_CIPHER_CTX * ctx, const unsigned char *key, const unsigned char *iv, int enc);
// int aes256_cbc_do_cipher(EVP_CIPHER_CTX * ctx, unsigned char *out, const unsigned char *in, size_t inlen);
// int aes256_cbc_cleanup(EVP_CIPHER_CTX *ctx);

// /* chacha20 mapping*/
// int chacha20_init(EVP_CIPHER_CTX * ctx, const unsigned char *key, const unsigned char *iv, int enc);
// int chacha20_do_cipher(EVP_CIPHER_CTX * ctx, unsigned char *out, const unsigned char *in, size_t inlen);
// int chacha20_cleanup(EVP_CIPHER_CTX *ctx);





// // Loads the specified EC key into private key pointer
// EVP_PKEY* load_ec_key(const char* keyfile);




// // init
// int ecdsa_init(EVP_PKEY_CTX *ctx);




// static EVP_MD_CTX* mdctx = NULL;

// // sign init
// int ecdsa_digestsign_init(EVP_PKEY_CTX *ctx)
// {   
//     // EVP_MD* md = NULL;
//     // EVP_PKEY* key = NULL;

//     // mdctx = EVP_MD_CTX_new();
//     // key = EVP_PKEY_CTX_get0_pkey(ctx); 
//     // int ret = EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, key);

//     // return ret;
//     return 1;
// }

// // sign 
// int ecdsa_digestsign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen)
// {
//     // int ret = EVP_DigestSign(mdctx, sig, siglen, tbs, tbslen);
//     // return ret;
//     return 1;
// }

// // cleanup 
// int ecdsa_cleanup(EVP_PKEY_CTX *ctx)
// {
//     EVP_MD_CTX_free(mdctx);
//     return 1;
// }

// wrapper for c++
#ifdef __cplusplus
}
#endif

#endif /* ENGINE_WRAP_H */