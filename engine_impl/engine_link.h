#include <openssl/ec.h>
#include <openssl/evp.h>
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

/* aes256 cbc mapping*/
int aes256_cbc_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                    const unsigned char *iv, int enc);
int aes256_cbc_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                         const unsigned char *in, size_t inlen);
int aes256_cbc_cleanup(EVP_CIPHER_CTX *ctx);
size_t aes256_cbc_size();

/* aes256 gcm mapping*/
int aes256_gcm_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                    const unsigned char *iv, int enc);
int aes256_gcm_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                         const unsigned char *in, size_t inlen);
int aes256_gcm_cleanup(EVP_CIPHER_CTX *ctx);
size_t aes256_gcm_size();

/* chacha20 mapping*/
int chacha20_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                  const unsigned char *iv, int enc);
int chacha20_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                       const unsigned char *in, size_t inlen);
int chacha20_cleanup(EVP_CIPHER_CTX *ctx);
size_t chacha20_size();

/* private key loader */
EVP_PKEY *load_private_key(const char *keyfile);
/* public key loader */
EVP_PKEY *load_public_key(const char *keyfile);
/* certificate loader */
int load_certificate(ENGINE *engine, SSL *ssl, STACK_OF(X509_NAME) * ca_dn,
                     X509 **pcert, EVP_PKEY **pkey, STACK_OF(X509) * *pother,
                     UI_METHOD *ui_method, void *callback_data);

/* ecdsa mapping */
int ecdsa_init(EVP_PKEY_CTX *ctx);
int ecdsa_cleanup(EVP_PKEY_CTX *ctx);
int ecdsa_signctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx);
int ecdsa_signctx(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                  EVP_MD_CTX *mctx);
int ecdsa_verifyctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx);
int ecdsa_verifyctx(EVP_PKEY_CTX *ctx, const unsigned char *sig, int siglen,
                    EVP_MD_CTX *mctx);
int ecdsa_custom_digest(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx);
int ecdsa_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2);

/* ecdh mapping */
int ecdh_derive_init(EVP_PKEY_CTX *ctx);
int ecdh_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);
int ecdh_set_peer(EC_KEY *other_key);
int ecdh_get_shared_secret();

/* ec methods */
int ec_verify_sig(const unsigned char *dgst, int dgst_len, const ECDSA_SIG *sig,
                  EC_KEY *eckey);
int ec_verify(int type, const unsigned char *dgst, int dgst_len,
              const unsigned char *sigbuf, int sig_len, EC_KEY *eckey);
ECDSA_SIG *ec_sign_sig(const unsigned char *dgst, int dgst_len,
                       const BIGNUM *in_kinv, const BIGNUM *in_r,
                       EC_KEY *eckey);
int ec_sign_setup(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp, BIGNUM **rp);
int ec_sign(int type, const unsigned char *dgst, int dlen, unsigned char *sig,
            unsigned int *siglen, const BIGNUM *kinv, const BIGNUM *r,
            EC_KEY *eckey);
int ec_copy(EC_KEY *dest, const EC_KEY *src);
int ec_set_public(EC_KEY *key, const EC_POINT *pub_key);
int ec_set_private(EC_KEY *key, const BIGNUM *priv_key);
int ec_set_group(EC_KEY *key, const EC_GROUP *grp);
void ec_finish(EC_KEY *key);
int ec_init(EC_KEY *key);
int ec_keygen(EC_KEY *key);
int ec_compute_key(unsigned char **psec, size_t *pseclen,
                   const EC_POINT *pub_key, const EC_KEY *ecdh);

/* engine startup shutdown */
int init();
int finish();
int ctrl_cmd_string(ENGINE *e, int cmd, long i, void *p, void (*f)(void));

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