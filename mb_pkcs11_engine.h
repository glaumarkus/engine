#ifndef MB_PKCS11_ENGINE_H_
#define MB_PKCS11_ENGINE_H_

#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/ossl_typ.h>
#include <openssl/sha.h>
#include <openssl/ecdsa.h>
#include <openssl/ec.h>
#include <string.h>


/* Init / Finish / Cmd */
static int engine_init(ENGINE* engine);
static int engine_finish(ENGINE* engine);
static int engine_ctrl_cmd_string(ENGINE* e, int cmd, long i, void* p, void (*f)(void));

/* Random functions */
static int engine_random_status(void);
static int engine_get_random_bytes(unsigned char *buffer, int num);

/* Selectors */
static int engine_digest_selector(ENGINE *e, const EVP_MD **digest,
        const int **nids, int nid);
static int engine_cipher_selector(ENGINE *e, const EVP_CIPHER **cipher, 
        const int **nids, int nid);
static int engine_pkey_selector(ENGINE *e, EVP_PKEY_METHOD **method,
        const int **nids, int nid);

// static int engine_ec_selector(ENGINE *e, EVP_PKEY_METHOD **method,
//         const int **nids, int nid);


/* sha256 mapping */
static inline int engine_sha256_init(EVP_MD_CTX *ctx);
static inline int engine_sha256_update(EVP_MD_CTX *ctx, const void *in, size_t len);
static inline int engine_sha256_final(EVP_MD_CTX *ctx, unsigned char *md);
static inline int engine_sha256_cleanup(EVP_MD_CTX *ctx);
static const EVP_MD* init_engine_sha256_method(void);

/* sha384 mapping */
static inline int engine_sha384_init(EVP_MD_CTX *ctx);
static inline int engine_sha384_update(EVP_MD_CTX *ctx, const void *in, size_t len);
static inline int engine_sha384_final(EVP_MD_CTX *ctx, unsigned char *md);
static inline int engine_sha384_cleanup(EVP_MD_CTX *ctx);
static const EVP_MD* init_engine_sha384_method(void);

/* aes 256 cbc mapping */
static inline int engine_aes256_cbc_init(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc);
static inline int engine_aes256_cbc_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inlen);
static inline int engine_aes256_cbc_cleanup(EVP_CIPHER_CTX *ctx);
static const EVP_CIPHER* init_engine_aes256_cbc_method(void);

/* chacha20 mapping */
static inline int engine_chacha20_init(EVP_CIPHER_CTX * ctx, const unsigned char *key, const unsigned char *iv, int enc);
static inline int engine_chacha20_do_cipher(EVP_CIPHER_CTX * ctx, unsigned char *out, const unsigned char *in, size_t inlen);
static inline int engine_chacha20_cleanup(EVP_CIPHER_CTX *ctx);
static const EVP_CIPHER* init_engine_chacha20_method(void);

/* Loaders */
static EVP_PKEY *engine_load_private_key(ENGINE *engine, const char *key_id,
                              UI_METHOD *ui_method, void *callback_data);

                              
// static int engine_load_certificate(ENGINE *engine, SSL *ssl, STACK_OF(X509_NAME) *ca_dn,
// X509 **pcert, EVP_PKEY **pkey, STACK_OF(X509) **pother,
// UI_METHOD *ui_method, void *callback_data);


/* pkey mapping */
static inline int engine_ecdsa_init(EVP_PKEY_CTX *ctx);
static inline int engine_ecdsa_digest_sign(EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen);
static inline void engine_ecdsa_cleanup(EVP_PKEY_CTX *ctx);
static EVP_PKEY_METHOD* init_ecdsa_method();





/*
* ECDH
*/
// static int engine_ecdh_method_init(EVP_PKEY_CTX *ctx)
// {
//     printf("engine_ecdh_method_init called!\n");
//     return 1;
// }

// static int engine_ecdh_method_derive_init(EVP_PKEY_CTX *ctx)
// {
//     printf("engine_ecdh_method_derive_init called!\n");
//     return 1;
// }

// static int engine_ecdh_method_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keyLen)
// {
//     printf("engine_ecdh_method_derive called!\n");
//     return 1;
// }

// static void engine_ecdh_method_cleanup(EVP_PKEY_CTX *ctx)
// {
//     printf("engine_ecdh_method_cleanup called!\n");
// }


// ToDo
// static EVP_PKEY_METHOD* ecdh_method = NULL;
// static EVP_PKEY_METHOD* init_ecdh_method(){
//     printf("init_ecdh_method called!\n");
//     ecdh_method = EVP_PKEY_meth_new(NID_brainpoolP384r1, EVP_PKEY_FLAG_AUTOARGLEN);
//     EVP_PKEY_meth_set_init(ecdh_method, engine_ecdh_method_init);
//     EVP_PKEY_meth_set_derive(ecdh_method, engine_ecdh_method_derive_init, engine_ecdh_method_derive);
//     EVP_PKEY_meth_set_cleanup(ecdh_method, engine_ecdh_method_cleanup);
//     return ecdh_method;
// };


#endif /* MB_PKCS11_ENGINE_H_ */