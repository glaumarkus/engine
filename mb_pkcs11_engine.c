// include engine
#include "mb_pkcs11_engine.h"

// local includes
#include "engine_link.h"

// defines
#define PRINT_DEBUG

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
        // this comes out when calling with the key & sha256
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
        EVP_PKEY_meth_set_verifyctx(engine_ecdsa_method, )
    }
    return engine_ecdsa_method;
};


/*
* This gets called when the engine is bound from another program
*/
int engine_bind(ENGINE * e, const char *id)
{
    printf("[Engine]: engine_bind called\n");
    if (!ENGINE_set_id(e, mb_engine_id) ||
        !ENGINE_set_name(e, mb_engine_name) ||
        !ENGINE_set_init_function(e, engine_init) ||
        !ENGINE_set_finish_function(e, engine_finish) ||
        !ENGINE_set_RAND(e, &engine_random_method) ||
        !ENGINE_set_digests(e, &engine_digest_selector) ||
        !ENGINE_set_ciphers(e, &engine_cipher_selector) ||
        !ENGINE_set_load_privkey_function(e, &engine_load_private_key) ||
        !ENGINE_set_pkey_meths(e, &engine_pkey_selector) 
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
    
    printf("[Engine]: engine_digest_selector called!\n");
    int ok = 1;

    if (!digest) {
        *nids = digest_ids;
        printf("[Engine]: \n Digest is empty! Nid:%d\n", nid);
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
    printf("[Engine]: engine_cipher_selector called!\n");
    int ok = 1;

    if (!cipher)
    {
        *nids = cipher_ids;
        printf("[Engine]: \n Cipher is empty! Nid:%d\n", nid);
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
    printf("[Engine]: engine_load_private_key called!\n");
    return load_ec_key(key_id);
}





/*
* Method implementations
*/

/* sha256 method */
static EVP_MD* engine_sha256_method = NULL;
static const EVP_MD* init_engine_sha256_method(void)
{
    printf("[Engine]: init_engine_sha256_method called\n");
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
    printf("[Engine]: engine_sha256_init called!\n");
    return sha256_init(ctx);
}
static inline int engine_sha256_update(EVP_MD_CTX *ctx, const void *in, size_t len)
{
    printf("[Engine]: engine_sha256_update called!\n");
    return sha256_update(ctx, in, len);
}
static inline int engine_sha256_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    printf("[Engine]: engine_sha256_final called!\n");
    return sha256_final(ctx, md);
}
static inline int engine_sha256_cleanup(EVP_MD_CTX *ctx)
{
    printf("[Engine]: engine_sha256_cleanup called!\n");
    return sha256_cleanup(ctx);
}


/* sha384 method */
static EVP_MD* engine_sha384_method = NULL;
static const EVP_MD* init_engine_sha384_method(void)
{
    printf("[Engine]: init_engine_sha384_method called\n");
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
    printf("[Engine]: engine_sha384_init called!\n");
    return sha384_init(ctx);
}
static inline int engine_sha384_update(EVP_MD_CTX *ctx, const void *in, size_t len)
{
    printf("[Engine]: engine_sha384_update called!\n");
    return sha384_update(ctx, in, len);
}
static inline int engine_sha384_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    printf("[Engine]: engine_sha384_final called!\n");
    return sha384_final(ctx, md);
}
static inline int engine_sha384_cleanup(EVP_MD_CTX *ctx)
{
    printf("[Engine]: engine_sha384_cleanup called!\n");
    return sha384_cleanup(ctx);
}


/* aes 256 cbc method */
static EVP_CIPHER* engine_aes256_cbc_method = NULL;
static const EVP_CIPHER* init_engine_aes256_cbc_method(void)
{
    printf("[Engine]: init_engine_aes256_cbc_method called!\n");
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
    printf("[Engine]: engine_aes256_cbc_init called!\n");
    return aes256_cbc_init(ctx, key, iv, enc); 
}
static inline int engine_aes256_cbc_do_cipher(EVP_CIPHER_CTX * ctx, unsigned char *out,
		const unsigned char *in, size_t inlen)
{
    printf("[Engine]: engine_aes256_cbc_do_cipher called !\n");
    return aes256_cbc_do_cipher(ctx, out, in, inlen);
}
static inline int engine_aes256_cbc_cleanup(EVP_CIPHER_CTX *ctx)
{
    printf("[Engine]: engine_aes256_cbc_cleanup called!\n");
    return aes256_cbc_cleanup(ctx); 
}


/* chacha20 method */
static EVP_CIPHER* engine_chacha20_method = NULL;
static const EVP_CIPHER* init_engine_chacha20_method(void)
{
    printf("[Engine]: engine_chacha20_method called!\n");
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
    printf("[Engine]: engine_chacha20_init called!\n");
    return chacha20_init(ctx, key, iv, enc); 
}
static inline int engine_chacha20_do_cipher(EVP_CIPHER_CTX * ctx, unsigned char *out,
		const unsigned char *in, size_t inlen)
{
    printf("[Engine]: engine_chacha20_do_cipher called!\n");
    return chacha20_do_cipher(ctx, out, in, inlen);
}
static inline int engine_chacha20_cleanup(EVP_CIPHER_CTX *ctx)
{
    printf("[Engine]: engine_chacha20_cleanup called!\n");
    return chacha20_cleanup(ctx); 
}








/*
* This will be used to get the token / id of the private key
*/
// static int engine_ctrl_cmd_string(ENGINE* e, const char* cmd_name, const char* cmd_value)
// static int engine_ctrl_cmd_string(ENGINE* e, int cmd, long i, void* p, void (*f)(void))
// {
//     printf("[Engine]: engine_ctrl_cmd_string called!\n");
//     return 0;
// }




// static int engine_load_certificate(ENGINE *engine, SSL *ssl, STACK_OF(X509_NAME) *ca_dn,
//                               X509 **pcert, EVP_PKEY **pkey, STACK_OF(X509) **pother,
//                               UI_METHOD *ui_method, void *callback_data) {
//     printf("[Engine]: engine_load_certificate called!\n");
//     int result = 0;
//     if (engine != NULL && pcert != NULL && pkey != NULL) {
//         result = 1;
//     }

//     return result;
// }





static int engine_init(ENGINE* engine)
{
    printf("[Engine]: engine_init called\n");
    return 1;
}

static int engine_finish(ENGINE* engine)
{
    printf("[Engine]: engine_finish called\n");
    return 1;
}












// /* Define the ECDSA method */
// static int myengine_ecdsa_init(EVP_PKEY_CTX *ctx) {
//     printf("[Engine]: myengine_ecdsa_init called!\n");

//     // const EVP_MD *md = NULL;
//     // EVP_PKEY* key = EVP_PKEY_CTX_get0_pkey(ctx);
//     // int key_id = EVP_PKEY_id(key);

//     // int ret = EVP_PKEY_CTX_get_signature_md(ctx, &md);

    
//     // ret = EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP_SIGN, EVP_PKEY_CTRL_GET_MD, 0, (void *)&md);

//     // // find 672
//     // EVP_MD* method = EVP_MD_meth_new(NID_sha256,NID_undef);
//     // unsigned long l = EVP_MD_meth_get_flags(method);
//     // EVP_PKEY_CTX_get_signature_md(ctx, method); 
//     // //engine_digest_selector(NULL, &method, NULL, method);

//     return ecdsa_digestsign_init(ctx);
// }

// static int myengine_ecdsa_digest_sign(EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen)
// {
//     printf("[Engine]: myengine_ecdsa_digest_sign called!\n");
//     return ecdsa_digestsign(ctx, sig, siglen, tbs, tbslen);
// }

// static void myengine_ecdsa_cleanup(EVP_PKEY_CTX *ctx) {
//     printf("[Engine]: myengine_ecdsa_cleanup called!\n");
// }

// static EVP_PKEY_METHOD* ecdsa_method = NULL;
// static EVP_PKEY_METHOD* init_ecdsa_method(){
//     printf("[Engine]: init_ecdsa_method called!\n");
//     ecdsa_method = EVP_PKEY_meth_new(NID_brainpoolP384r1, EVP_PKEY_FLAG_AUTOARGLEN);
//     EVP_PKEY_meth_set_init(ecdsa_method, myengine_ecdsa_init);
//     EVP_PKEY_meth_set_cleanup(ecdsa_method, myengine_ecdsa_cleanup); 
//     EVP_PKEY_meth_set_digestsign(ecdsa_method, myengine_ecdsa_digest_sign);
    

//     return ecdsa_method;
// };

// int engine_sign(int type, const unsigned char *dgst, int dlen, unsigned char *sig,
//             unsigned int *siglen, const BIGNUM *kinv, const BIGNUM *r, EC_KEY *eckey)
// {
//     return 1;
// }

// int engine_sign_sign_setup(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp, BIGNUM **rp)
// {
//     return 1;
// }

// ECDSA_SIG *engine_sign_sign_sig(const unsigned char *dgst, int dgst_len,
//                        const BIGNUM *in_kinv, const BIGNUM *in_r, EC_KEY *eckey)
// {
//     return NULL;
// }


// static EC_KEY_METHOD* ecdsa_method = NULL;
// static EC_KEY_METHOD* init_ecdsa_method()
// {
//     printf("[Engine]: init_ecdsa_method called\n");
//     ecdsa_method = EC_KEY_METHOD_new(EC_KEY_OpenSSL());
//     EC_KEY_METHOD_set_sign(ecdsa_method, engine_sign, engine_sign_sign_setup, engine_sign_sign_sig);
//     return ecdsa_method;
// }



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

// static int pkey_methods_ids[] = {NID_brainpoolP384r1};
// static int engine_pkey_selector(ENGINE *e, EVP_PKEY_METHOD **method,
//         const int **nids, int nid) {
    
//     printf("[Engine]: engine_pkey_selector called!\n");
//     int ok = 1;

//     if (!method) {
//         *nids = pkey_methods_ids;
//         printf("[Engine]: \n Method is empty! Nid:%d\n", nid);
//         return 2;
//     }

//     switch (nid)
//     {
//         // call for ctx creation
//         case NID_X9_62_id_ecPublicKey:
//             *method = init_ecdsa_method();
//             break;

//         case NID_brainpoolP384r1:
//             printf("[Engine]: DigestSelector chose sha256\n");
//             //*method = init_ecdh_method();
//             break;
//         default:
//             *method = NULL;
//             ok = 0;
//     }

//     return ok;
// }



/*
* Return the state of the random engine machine, since using the PSC we would indicate positive return
*/
static int engine_random_status(void)
{
    printf("[Engine]: engine_random_status called\n");
    return 1;
}

/*
* TRNG function to receive bytes, check on NV hsm if there is a minimun entropy that is required
*/
static int engine_get_random_bytes(unsigned char *buffer, int num) {
    printf("[Engine]: engine_get_random_bytes called for %d bytes\n", num);
    return RAND_bytes(buffer, sizeof(num));
}

