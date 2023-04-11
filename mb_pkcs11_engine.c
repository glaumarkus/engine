// include engine
#include "mb_pkcs11_engine.h"

// local includes
#include "engine_link.h"

// defines
// #define PRINT_DEBUG

static const char *mb_engine_id = "MB_PKCS11_ENGINE";
static const char *mb_engine_name = "MB.OS custom PKCS11 Engine";

RAND_METHOD engine_random_method = {
        NULL,                       /* seed */
        engine_get_random_bytes,    /* bytes */
        NULL,                       /* cleanup */
        NULL,                       /* add */
        NULL,                       /* pseudorand */
        engine_random_status        /* status */
};


static int pkey_methods_ids[] = {NID_X9_62_id_ecPublicKey};
static int engine_pkey_selector(ENGINE *e, EVP_PKEY_METHOD **method,
        const int **nids, int nid) {
#ifdef PRINT_DEBUG
    printf("[Engine]: engine_pkey_selector called!\n");
#endif
    int ok = 1;

    if (!method) {
        *nids = pkey_methods_ids;
        printf("[Engine]: \n Method is empty! Nid:%d\n", nid);
        return 2;
    }

    switch (nid)
    {
        // this comes out when calling with EC_KEY
        case NID_X9_62_id_ecPublicKey:
            *method = init_ecdsa_method();
            break;
        default:
            *method = NULL;
            ok = 0;
    }

    return ok;
}


static inline int engine_ecdsa_init(EVP_PKEY_CTX *ctx)
{
#ifdef PRINT_DEBUG
    printf("[Engine]: engine_ecdsa_cleanup called!\n");
#endif    
    return ecdsa_init(ctx);
}
static inline void engine_ecdsa_cleanup(EVP_PKEY_CTX *ctx) {
#ifdef PRINT_DEBUG
    printf("[Engine]: engine_ecdsa_cleanup called!\n");
#endif    
    ecdsa_cleanup(ctx);
}

static inline int engine_ecdsa_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
#ifdef PRINT_DEBUG
    printf("[Engine]: engine_ecdsa_ctrl called!\n");
#endif
    return ecdsa_ctrl(ctx, type, p1, p2);
}

static inline int engine_ecdsa_ctrl_str(EVP_PKEY_CTX *ctx, const char *type, const char *value)
{
#ifdef PRINT_DEBUG
    printf("[Engine]: engine_ecdsa_ctrl_str called!\n");
#endif
    return 1;
}

static inline int engine_ecdsa_digest_custom(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx)
{
#ifdef PRINT_DEBUG
    printf("[Engine]: engine_ecdsa_digest_custom called!\n");
#endif
    return ecdsa_custom_digest(ctx, mctx);
}

static inline int engine_signctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx)
{
#ifdef PRINT_DEBUG
    printf("[Engine]: engine_signctx_init called!\n");
#endif
    return ecdsa_signctx_init(ctx, mctx);
}

static inline int engine_signctx(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, EVP_MD_CTX *mctx)
{
#ifdef PRINT_DEBUG
    printf("[Engine]: engine_signctx called!\n");
#endif
    return ecdsa_signctx(ctx, sig, siglen, mctx);
}

static inline int engine_verifyctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx)
{
#ifdef PRINT_DEBUG
    printf("[Engine]: engine_signctx called!\n");
#endif
    return ecdsa_verifyctx_init(ctx, mctx);
}

static inline int engine_verifyctx(EVP_PKEY_CTX *ctx, const unsigned char *sig, int siglen, EVP_MD_CTX *mctx)
{
#ifdef PRINT_DEBUG
    printf("[Engine]: engine_signctx called!\n");
#endif
    return ecdsa_verifyctx(ctx, sig, siglen, mctx);
}

static EVP_PKEY_METHOD* engine_ecdsa_method = NULL;
static EVP_PKEY_METHOD* init_ecdsa_method(){
#ifdef PRINT_DEBUG
    printf("[Engine]: init_ecdsa_method called!\n");
#endif
    if (engine_ecdsa_method == NULL)
    {
        engine_ecdsa_method = EVP_PKEY_meth_new(NID_brainpoolP384r1, EVP_PKEY_FLAG_AUTOARGLEN);
        EVP_PKEY_meth_set_init(engine_ecdsa_method, engine_ecdsa_init);
        EVP_PKEY_meth_set_cleanup(engine_ecdsa_method, engine_ecdsa_cleanup); 
        EVP_PKEY_meth_set_ctrl(engine_ecdsa_method, engine_ecdsa_ctrl, engine_ecdsa_ctrl_str);
        EVP_PKEY_meth_set_digest_custom(engine_ecdsa_method, engine_ecdsa_digest_custom);
        EVP_PKEY_meth_set_signctx(engine_ecdsa_method, engine_signctx_init, engine_signctx);
        EVP_PKEY_meth_set_verifyctx(engine_ecdsa_method, engine_verifyctx_init, engine_verifyctx);
    }
    return engine_ecdsa_method;
};

static inline const EC_KEY_METHOD* engine_ec_key_method()
{
    return NULL;
}
/*
* This gets called when the engine is bound from another program
*/
int engine_bind(ENGINE * e, const char *id)
{
#ifdef PRINT_DEBUG
    printf("[Engine]: engine_bind called\n");
#endif
    if (!ENGINE_set_id(e, mb_engine_id) ||
        !ENGINE_set_name(e, mb_engine_name) ||
        !ENGINE_set_init_function(e, engine_init) ||
        !ENGINE_set_finish_function(e, engine_finish) ||
        !ENGINE_set_RAND(e, &engine_random_method) ||
        !ENGINE_set_digests(e, &engine_digest_selector) ||
        !ENGINE_set_ciphers(e, &engine_cipher_selector) ||
        !ENGINE_set_load_privkey_function(e, &engine_load_private_key) ||
        !ENGINE_set_load_pubkey_function(e, &engine_load_public_key) || 
        !ENGINE_set_pkey_meths(e, &engine_pkey_selector) 
        // ||
        // !ENGINE_set_EC(e, &engine_ec_key_method)
        // !ENGINE_set_ctrl_function(e, engine_ctrl_cmd_string) ||
        // !ENGINE_set_load_ssl_client_cert_function(e, &engine_load_certificate) ||
        // !ENGINE_set_EC(e, ecdsa_method) ||
        // !ENGINE_set_DSA(e, dsa_method)
        )
        return 0;
    // now bind the ec stuff??
    //ECDH_METHOD *ecdh_method = ECDH_METHOD_new(EC_KEY_OpenSSL());

    return 1;
}


IMPLEMENT_DYNAMIC_BIND_FN(engine_bind)
IMPLEMENT_DYNAMIC_CHECK_FN()


/* digest selector */ 
static int digest_ids[] = {NID_sha256, NID_sha3_384};
static int engine_digest_selector(ENGINE *e, const EVP_MD **digest,
        const int **nids, int nid) {
#ifdef PRINT_DEBUG
    printf("[Engine]: engine_digest_selector called!\n");
#endif
    int ok = 1;

    if (!digest) {
        *nids = digest_ids;
#ifdef PRINT_DEBUG
        printf("[Engine]: \n Digest is empty! Nid:%d\n", nid);
#endif
        return 2;
    }

    switch (nid)
    {
        case NID_sha256:
            *digest = init_engine_sha256_method();
            break;
        case NID_sha3_384:
            *digest = init_engine_sha384_method();
            break;
        default:
            *digest = NULL;
            ok = 0;
    }

    return ok;
}

/* cipher selector */ 
static int cipher_ids[] = {NID_aes_256_cbc, NID_chacha20};
static int engine_cipher_selector(ENGINE *e, const EVP_CIPHER **cipher, const int **nids, int nid)
{
#ifdef PRINT_DEBUG
    printf("[Engine]: engine_cipher_selector called!\n");
#endif
    int ok = 1;

    if (!cipher)
    {
        *nids = cipher_ids;
#ifdef PRINT_DEBUG
        printf("[Engine]: \n Cipher is empty! Nid:%d\n", nid);
#endif
        return 2;
    }
    
    switch (nid)
    {
        case NID_aes_256_cbc:
            *cipher = init_engine_aes256_cbc_method();
            break;
        case NID_chacha20:
            *cipher = init_engine_chacha20_method();
            break;
        default:
            *cipher = NULL;
            ok = 0;
    }
    return ok;
}


static EVP_PKEY *engine_load_private_key(ENGINE *engine, const char *key_id,
                              UI_METHOD *ui_method, void *callback_data) {
#ifdef PRINT_DEBUG
    printf("[Engine]: engine_load_private_key called!\n");
#endif
    return load_ec_key(key_id);
}

static EVP_PKEY *engine_load_public_key(ENGINE *engine, const char *key_id,
                              UI_METHOD *ui_method, void *callback_data) {
#ifdef PRINT_DEBUG
    printf("[Engine]: engine_load_public_key called!\n");
#endif
    return load_ec_key_public(key_id);
}





/*
* Method implementations
*/

/* sha256 method */
static EVP_MD* engine_sha256_method = NULL;
static const EVP_MD* init_engine_sha256_method(void)
{
#ifdef PRINT_DEBUG
    printf("[Engine]: init_engine_sha256_method called\n");
#endif
    if (engine_sha256_method == NULL)
    {
        engine_sha256_method = EVP_MD_meth_new(NID_sha256, NID_undef);
        EVP_MD_meth_set_result_size(engine_sha256_method, 32);
        EVP_MD_meth_set_input_blocksize(engine_sha256_method, 64);
        EVP_MD_meth_set_init(engine_sha256_method, engine_sha256_init);
        EVP_MD_meth_set_update(engine_sha256_method, engine_sha256_update);
        EVP_MD_meth_set_final(engine_sha256_method, engine_sha256_final);
        EVP_MD_meth_set_cleanup(engine_sha256_method, engine_sha256_cleanup);
        EVP_MD_meth_set_app_datasize(engine_sha256_method, sha256_size()); 

    }
    return engine_sha256_method;
}
static inline int engine_sha256_init(EVP_MD_CTX *ctx)
{
#ifdef PRINT_DEBUG
    printf("[Engine]: engine_sha256_init called!\n");
#endif
    return sha256_init(ctx);
}
static inline int engine_sha256_update(EVP_MD_CTX *ctx, const void *in, size_t len)
{
#ifdef PRINT_DEBUG
    printf("[Engine]: engine_sha256_update called!\n");
#endif
    return sha256_update(ctx, in, len);
}
static inline int engine_sha256_final(EVP_MD_CTX *ctx, unsigned char *md)
{
#ifdef PRINT_DEBUG
    printf("[Engine]: engine_sha256_final called!\n");
#endif
    return sha256_final(ctx, md);
}
static inline int engine_sha256_cleanup(EVP_MD_CTX *ctx)
{
#ifdef PRINT_DEBUG
    printf("[Engine]: engine_sha256_cleanup called!\n");
#endif
    return sha256_cleanup(ctx);
}


/* sha384 method */
static EVP_MD* engine_sha384_method = NULL;
static const EVP_MD* init_engine_sha384_method(void)
{
#ifdef PRINT_DEBUG
    printf("[Engine]: init_engine_sha384_method called\n");
#endif
    if (engine_sha384_method == NULL)
    {
        engine_sha384_method = EVP_MD_meth_new(NID_sha384, NID_undef);
        EVP_MD_meth_set_result_size(engine_sha384_method, 48);
        EVP_MD_meth_set_input_blocksize(engine_sha384_method, 64);
        EVP_MD_meth_set_init(engine_sha384_method, engine_sha384_init);
        EVP_MD_meth_set_update(engine_sha384_method, engine_sha384_update);
        EVP_MD_meth_set_final(engine_sha384_method, engine_sha384_final);
        EVP_MD_meth_set_cleanup(engine_sha384_method, engine_sha384_cleanup);
        EVP_MD_meth_set_app_datasize(engine_sha384_method, sha384_size()); 
    }
    return engine_sha384_method;
}
static inline int engine_sha384_init(EVP_MD_CTX *ctx)
{
#ifdef PRINT_DEBUG
    printf("[Engine]: engine_sha384_init called!\n");
#endif
    return sha384_init(ctx);
}
static inline int engine_sha384_update(EVP_MD_CTX *ctx, const void *in, size_t len)
{
#ifdef PRINT_DEBUG
    printf("[Engine]: engine_sha384_update called!\n");
#endif
    return sha384_update(ctx, in, len);
}
static inline int engine_sha384_final(EVP_MD_CTX *ctx, unsigned char *md)
{
#ifdef PRINT_DEBUG
    printf("[Engine]: engine_sha384_final called!\n");
#endif
    return sha384_final(ctx, md);
}
static inline int engine_sha384_cleanup(EVP_MD_CTX *ctx)
{
#ifdef PRINT_DEBUG
    printf("[Engine]: engine_sha384_cleanup called!\n");
#endif
    return sha384_cleanup(ctx);
}


/* aes 256 cbc method */
static EVP_CIPHER* engine_aes256_cbc_method = NULL;
static const EVP_CIPHER* init_engine_aes256_cbc_method(void)
{
#ifdef PRINT_DEBUG
    printf("[Engine]: init_engine_aes256_cbc_method called!\n");
#endif
    if (engine_aes256_cbc_method == NULL)
    {
        engine_aes256_cbc_method = EVP_CIPHER_meth_new(NID_aes_256_cbc, 16, 32);
        EVP_CIPHER_meth_set_iv_length(engine_aes256_cbc_method, 16);
        EVP_CIPHER_meth_set_flags(engine_aes256_cbc_method, EVP_CIPH_CBC_MODE);
        EVP_CIPHER_meth_set_init(engine_aes256_cbc_method, engine_aes256_cbc_init);
        EVP_CIPHER_meth_set_do_cipher(engine_aes256_cbc_method, engine_aes256_cbc_do_cipher);
        EVP_CIPHER_meth_set_cleanup(engine_aes256_cbc_method, engine_aes256_cbc_cleanup);
        EVP_CIPHER_meth_set_impl_ctx_size(engine_aes256_cbc_method, aes256_cbc_size());
    }
    return engine_aes256_cbc_method;
}
static inline int engine_aes256_cbc_init(EVP_CIPHER_CTX * ctx, const unsigned char *key,
		const unsigned char *iv, int enc)
{
#ifdef PRINT_DEBUG
    printf("[Engine]: engine_aes256_cbc_init called!\n");
#endif
    return aes256_cbc_init(ctx, key, iv, enc); 
}
static inline int engine_aes256_cbc_do_cipher(EVP_CIPHER_CTX * ctx, unsigned char *out,
		const unsigned char *in, size_t inlen)
{
#ifdef PRINT_DEBUG
    printf("[Engine]: engine_aes256_cbc_do_cipher called !\n");
#endif
    return aes256_cbc_do_cipher(ctx, out, in, inlen);
}
static inline int engine_aes256_cbc_cleanup(EVP_CIPHER_CTX *ctx)
{
#ifdef PRINT_DEBUG
    printf("[Engine]: engine_aes256_cbc_cleanup called!\n");
#endif
    return aes256_cbc_cleanup(ctx); 
}


/* chacha20 method */
static EVP_CIPHER* engine_chacha20_method = NULL;
static const EVP_CIPHER* init_engine_chacha20_method(void)
{
#ifdef PRINT_DEBUG
    printf("[Engine]: engine_chacha20_method called!\n");
#endif
    if (engine_chacha20_method == NULL)
    {
        engine_chacha20_method = EVP_CIPHER_meth_new(NID_chacha20, 1, 32);
        EVP_CIPHER_meth_set_iv_length(engine_chacha20_method, 16);
        EVP_CIPHER_meth_set_init(engine_chacha20_method, engine_chacha20_init);
        EVP_CIPHER_meth_set_do_cipher(engine_chacha20_method, engine_chacha20_do_cipher);
        EVP_CIPHER_meth_set_cleanup(engine_chacha20_method, engine_chacha20_cleanup);
    }
    return engine_chacha20_method;
}
static inline int engine_chacha20_init(EVP_CIPHER_CTX * ctx, const unsigned char *key,
		const unsigned char *iv, int enc)
{
#ifdef PRINT_DEBUG
    printf("[Engine]: engine_chacha20_init called!\n");
#endif
    return chacha20_init(ctx, key, iv, enc); 
}
static inline int engine_chacha20_do_cipher(EVP_CIPHER_CTX * ctx, unsigned char *out,
		const unsigned char *in, size_t inlen)
{
#ifdef PRINT_DEBUG
    printf("[Engine]: engine_chacha20_do_cipher called!\n");
#endif
    return chacha20_do_cipher(ctx, out, in, inlen);
}
static inline int engine_chacha20_cleanup(EVP_CIPHER_CTX *ctx)
{
#ifdef PRINT_DEBUG
    printf("[Engine]: engine_chacha20_cleanup called!\n");
#endif
    return chacha20_cleanup(ctx); 
}



static int engine_init(ENGINE* engine)
{
#ifdef PRINT_DEBUG
    printf("[Engine]: engine_init called\n");
#endif
    return 1;
}

static int engine_finish(ENGINE* engine)
{
#ifdef PRINT_DEBUG
    printf("[Engine]: engine_finish called\n");
#endif
    return 1;
}

/*
* Return the state of the random engine machine, since using the PSC we would indicate positive return
*/
static int engine_random_status(void)
{
#ifdef PRINT_DEBUG
    printf("[Engine]: engine_random_status called\n");
#endif
    return 1;
}

/*
* TRNG function to receive bytes, check on NV hsm if there is a minimun entropy that is required
*/
static int engine_get_random_bytes(unsigned char *buffer, int num) {
#ifdef PRINT_DEBUG
    printf("[Engine]: engine_get_random_bytes called for %d bytes\n", num);
#endif
    return RAND_bytes(buffer, sizeof(num));
}


// static DSA_SIG* dsa_sign(const unsigned char* in, int l, DSA* dsa)
// {
//     return NULL;
// }

// static DSA_METHOD *dsa_method = NULL;
// static DSA_METHOD* init_dsa_method()
// {
//     printf("[Engine]: init_dsa_method called\n");
    
//     dsa_method = DSA_meth_new("ECDSA", 0);
//     DSA_meth_set_sign(dsa_method, dsa_sign);
//     return dsa_method;
// }


