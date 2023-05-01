#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#ifndef ENGINE_WRAP_H
#define ENGINE_WRAP_H

// wrapper for c++
#ifdef __cplusplus
extern "C" {
#endif

/* buffer to pass an instance of the factory interface */
struct engine_factory_instance
{
    void* instance;
    size_t size;
};

/* engine startup shutdown */
void get_impl_size(size_t* size);
int init(struct engine_factory_instance* instance);
int finish(struct engine_factory_instance* instance);
int ctrl_cmd_string(struct engine_factory_instance* instance, ENGINE *e, int cmd, long i, void *p, void (*f)(void));


/* sha256 mapping */
int sha256_init(struct engine_factory_instance* instance, EVP_MD_CTX *ctx);
int sha256_update(EVP_MD_CTX *ctx, const void *in, size_t len);
int sha256_final(EVP_MD_CTX *ctx, unsigned char *md);
int sha256_cleanup(EVP_MD_CTX *ctx);
size_t sha256_size();

/* sha384 mapping */
int sha384_init(struct engine_factory_instance* instance, EVP_MD_CTX *ctx);
int sha384_update(EVP_MD_CTX *ctx, const void *in, size_t len);
int sha384_final(EVP_MD_CTX *ctx, unsigned char *md);
int sha384_cleanup(EVP_MD_CTX *ctx);
size_t sha384_size();

/* aes256 cbc mapping*/
int aes256_cbc_init(struct engine_factory_instance* instance, EVP_CIPHER_CTX *ctx, const unsigned char *key,
                    const unsigned char *iv, int enc);
int aes256_cbc_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                         const unsigned char *in, size_t inlen);
int aes256_cbc_cleanup(EVP_CIPHER_CTX *ctx);
size_t aes256_cbc_size();

/* aes256 gcm mapping*/
int aes256_gcm_init(struct engine_factory_instance* instance, EVP_CIPHER_CTX *ctx, const unsigned char *key,
                    const unsigned char *iv, int enc);
int aes256_gcm_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                         const unsigned char *in, size_t inlen);
int aes256_gcm_cleanup(EVP_CIPHER_CTX *ctx);
int aes256_gcm_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);
size_t aes256_gcm_size();

/* chacha20 mapping*/
int chacha20_init(struct engine_factory_instance* instance, EVP_CIPHER_CTX *ctx, const unsigned char *key,
                  const unsigned char *iv, int enc);
int chacha20_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                       const unsigned char *in, size_t inlen);
int chacha20_cleanup(EVP_CIPHER_CTX *ctx);
size_t chacha20_size();

/* private key loader */
EVP_PKEY *load_private_key(struct engine_factory_instance* instance, const char *keyfile);
/* public key loader */
EVP_PKEY *load_public_key(struct engine_factory_instance* instance, const char *keyfile);


/* ec functions */
int ec_init(struct engine_factory_instance* instance, EVP_PKEY_CTX *ctx);
int ec_cleanup(EVP_PKEY_CTX *ctx);
int ec_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2);

/* ecdsa functions */
int ec_signctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx);
int ec_signctx(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                  EVP_MD_CTX *mctx);
int ec_verifyctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx);
int ec_verifyctx(EVP_PKEY_CTX *ctx, const unsigned char *sig, int siglen,
                    EVP_MD_CTX *mctx);
int ec_custom_digest(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx);

/* ecdh functions */
int ec_derive_init(EVP_PKEY_CTX *ctx);
int ec_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);

/* ecdhe functions */
int ec_keygen_init(EVP_PKEY_CTX *ctx);
int ec_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);


/* engine random */
void rand_cleanup();
int rand_bytes(unsigned char *buf, int num);
int random_status();
int set_seed();

// wrapper for c++
#ifdef __cplusplus
}
#endif

#endif /* ENGINE_WRAP_H */