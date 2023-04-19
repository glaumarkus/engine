#ifndef MB_PKCS11_ENGINE_H_
#define MB_PKCS11_ENGINE_H_

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/sha.h>
#include <openssl/x509v3.h>
#include <string.h>

#define CMD_INIT_ARGS ENGINE_CMD_BASE
#define CMD_LOAD_CERT_CTRL (ENGINE_CMD_BASE + 1)

/* Init / Finish / Cmd */
static int engine_init(ENGINE *engine);
static int engine_finish(ENGINE *engine);
static int engine_ctrl_cmd_string(ENGINE *e, int cmd, long i, void *p,
                                  void (*f)(void));

/* Random functions */
static inline int engine_rand_set_seed(const void *buf, int num);
static inline int engine_rand_bytes(unsigned char *buf, int num);
static inline void engine_rand_cleanup(void);
static inline int engine_rand_add(const void *buf, int num, double randomness);
static inline int engine_rand_pseudorand(unsigned char *buf, int num);
static inline int engine_random_status(void);

/* Selectors */
static int engine_digest_selector(ENGINE *e, const EVP_MD **digest,
                                  const int **nids, int nid);
static int engine_cipher_selector(ENGINE *e, const EVP_CIPHER **cipher,
                                  const int **nids, int nid);
static int engine_pkey_selector(ENGINE *e, EVP_PKEY_METHOD **method,
                                const int **nids, int nid);

/* sha256 mapping */
static inline int engine_sha256_init(EVP_MD_CTX *ctx);
static inline int engine_sha256_update(EVP_MD_CTX *ctx, const void *in,
                                       size_t len);
static inline int engine_sha256_final(EVP_MD_CTX *ctx, unsigned char *md);
static inline int engine_sha256_cleanup(EVP_MD_CTX *ctx);
static const EVP_MD *init_engine_sha256_method(void);

/* sha384 mapping */
static inline int engine_sha384_init(EVP_MD_CTX *ctx);
static inline int engine_sha384_update(EVP_MD_CTX *ctx, const void *in,
                                       size_t len);
static inline int engine_sha384_final(EVP_MD_CTX *ctx, unsigned char *md);
static inline int engine_sha384_cleanup(EVP_MD_CTX *ctx);
static const EVP_MD *init_engine_sha384_method(void);

/* aes 256 cbc mapping */
static inline int engine_aes256_cbc_init(EVP_CIPHER_CTX *ctx,
                                         const unsigned char *key,
                                         const unsigned char *iv, int enc);
static inline int engine_aes256_cbc_do_cipher(EVP_CIPHER_CTX *ctx,
                                              unsigned char *out,
                                              const unsigned char *in,
                                              size_t inlen);
static inline int engine_aes256_cbc_cleanup(EVP_CIPHER_CTX *ctx);
static const EVP_CIPHER *init_engine_aes256_cbc_method(void);

/* aes 256 gcm mapping */
static inline int engine_aes256_gcm_init(EVP_CIPHER_CTX *ctx,
                                         const unsigned char *key,
                                         const unsigned char *iv, int enc);
static inline int engine_aes256_gcm_do_cipher(EVP_CIPHER_CTX *ctx,
                                              unsigned char *out,
                                              const unsigned char *in,
                                              size_t inlen);
static inline int engine_aes256_gcm_cleanup(EVP_CIPHER_CTX *ctx);
static const EVP_CIPHER *init_engine_aes256_gcm_method(void);

/* chacha20 mapping */
static inline int engine_chacha20_init(EVP_CIPHER_CTX *ctx,
                                       const unsigned char *key,
                                       const unsigned char *iv, int enc);
static inline int engine_chacha20_do_cipher(EVP_CIPHER_CTX *ctx,
                                            unsigned char *out,
                                            const unsigned char *in,
                                            size_t inlen);
static inline int engine_chacha20_cleanup(EVP_CIPHER_CTX *ctx);
static const EVP_CIPHER *init_engine_chacha20_method(void);

/* Asym Key Loaders */
static EVP_PKEY *engine_load_private_key(ENGINE *engine, const char *key_id,
                                         UI_METHOD *ui_method,
                                         void *callback_data);
static EVP_PKEY *engine_load_public_key(ENGINE *engine, const char *key_id,
                                        UI_METHOD *ui_method,
                                        void *callback_data);

/* certificate loader */
static int engine_load_certificate(ENGINE *engine, SSL *ssl,
                                   STACK_OF(X509_NAME) * ca_dn, X509 **pcert,
                                   EVP_PKEY **pkey, STACK_OF(X509) * *pother,
                                   UI_METHOD *ui_method, void *callback_data);

/* pkey mapping */
static inline int engine_signctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx);
static inline int engine_signctx(EVP_PKEY_CTX *ctx, unsigned char *sig,
                                 size_t *siglen, EVP_MD_CTX *mctx);

static inline int engine_verifyctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx);
static inline int engine_verifyctx(EVP_PKEY_CTX *ctx, const unsigned char *sig,
                                   int siglen, EVP_MD_CTX *mctx);

static inline int engine_ecdsa_digest_custom(EVP_PKEY_CTX *ctx,
                                             EVP_MD_CTX *mctx);

static inline int engine_ecdsa_ctrl(EVP_PKEY_CTX *ctx, int type, int p1,
                                    void *p2);
static inline int engine_ecdsa_ctrl_str(EVP_PKEY_CTX *ctx, const char *type,
                                        const char *value);

static inline int engine_ecdsa_init(EVP_PKEY_CTX *ctx);
static inline void engine_ecdsa_cleanup(EVP_PKEY_CTX *ctx);

static EVP_PKEY_METHOD *init_ecdsa_method();

#endif /* MB_PKCS11_ENGINE_H_ */