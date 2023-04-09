// include engine
#include "mb_pkcs11_engine.h"

// local includes
#include "engine_link.h"

static const char *mb_engine_id = "MB_PKCS11_ENGINE";
static const char *mb_engine_name = "MB.OS custom PKCS11 Engine";



/*
* This gets called when the engine is bound from another program
*/
int engine_bind(ENGINE * e, const char *id)
{
    printf("[Engine]: engine_bind called\n");
    if (!ENGINE_set_id(e, mb_engine_id) ||
        !ENGINE_set_name(e, mb_engine_name) ||
        // !ENGINE_set_ctrl_function(e, engine_ctrl_cmd_string) ||
        !ENGINE_set_init_function(e, engine_init) ||
        !ENGINE_set_finish_function(e, engine_finish) ||
        !ENGINE_set_RAND(e, &engine_random_method) ||
        !ENGINE_set_digests(e, &engine_digest_selector) 
        // !ENGINE_set_ciphers(e, &engine_cipher_selector) 
        // !ENGINE_set_pkey_meths(e, &engine_pkey_selector) ||
        // !ENGINE_set_load_privkey_function(e, &engine_load_private_key) ||
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
static int digest_ids[] = {NID_sha256, NID_sha384};
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
        // case NID_sha3_384:
        // //case NID_sha384:
        //     *digest = init_engine_sha384_method();
        //     break;
        case NID_sha3_384:
            *digest = init_engine_sha256_method();
            break;
        default:
            *digest = NULL;
            ok = 0;
    }

    return ok;
}

struct digest_ctx {
	SHA256_CTX ctx;
};

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
        EVP_MD_meth_set_app_datasize(engine_sha256_method, sizeof(struct digest_ctx)); 

    }
    return engine_sha256_method;
}

// cast to ctx
#define CTX_CAST(ctx) ((struct digest_ctx *)(EVP_MD_CTX_md_data(ctx)))

static inline int engine_sha256_init(EVP_MD_CTX *ctx)
{
    printf("engine_sha256_init called!\n");
    return SHA256_Init(&CTX_CAST(ctx)->ctx);
}

static inline int engine_sha256_update(EVP_MD_CTX *ctx, const void *in, size_t len)
{
    printf("engine_sha256_update called!\n");
    return SHA256_Update(&CTX_CAST(ctx)->ctx, in, len);
}

static inline int engine_sha256_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    printf("engine_sha256_final called!\n");
    return SHA256_Final(md, &CTX_CAST(ctx)->ctx);
}

static inline int engine_sha256_cleanup(EVP_MD_CTX *ctx)
{
    printf("engine_sha256_cleanup called!\n");
    return 1;
}


// /* sha256 methods */
// static inline int engine_sha256_init(EVP_MD_CTX *ctx)
// {
//     printf("[Engine]: engine_sha256_init called!\n");
//     return sha256_init(ctx);
// }

// static inline int engine_sha256_update(EVP_MD_CTX *ctx, const void *in, size_t len)
// {
//     printf("[Engine]: engine_sha256_update called!\n");
//     return sha256_update(ctx, in, len);
// }

// static inline int engine_sha256_final(EVP_MD_CTX *ctx, unsigned char *md)
// {
//     printf("[Engine]: engine_sha256_final called!\n");
//     return sha256_final(ctx, md);
// }

// static inline int engine_sha256_cleanup(EVP_MD_CTX *ctx)
// {
//     printf("[Engine]: engine_sha256_cleanup called!\n");
//     return sha256_cleanup(ctx);
// }


// /* sha384 method */
// static EVP_MD* engine_sha384_method = NULL;
// static const EVP_MD* init_engine_sha384_method(void)
// {
//     printf("[Engine]: init_engine_sha384_method called\n");
    
//     engine_sha384_method = EVP_MD_meth_new(NID_sha384, NID_undef);
//     EVP_MD_meth_set_result_size(engine_sha384_method, 48);
//     EVP_MD_meth_set_input_blocksize(engine_sha384_method, 64);
//     EVP_MD_meth_set_init(engine_sha384_method, engine_sha384_init);
//     EVP_MD_meth_set_update(engine_sha384_method, engine_sha384_update);
//     EVP_MD_meth_set_final(engine_sha384_method, engine_sha384_final);
//     EVP_MD_meth_set_cleanup(engine_sha384_method, engine_sha384_cleanup);
//     return engine_sha384_method;
// }

// /* aes 256 cbc method */
// static EVP_CIPHER* engine_aes256_cbc_method = NULL;
// static const EVP_CIPHER* init_engine_aes256_cbc_method(void)
// {
//     printf("[Engine]: init_engine_aes256_cbc_method called!\n");
//     engine_aes256_cbc_method = EVP_CIPHER_meth_new(NID_aes_256_cbc, 8, 32);
//     EVP_CIPHER_meth_set_iv_length(engine_aes256_cbc_method, 16);
//     EVP_CIPHER_meth_set_flags(engine_aes256_cbc_method, EVP_CIPH_CBC_MODE);
//     EVP_CIPHER_meth_set_init(engine_aes256_cbc_method, engine_aes256_cbc_init);
//     EVP_CIPHER_meth_set_do_cipher(engine_aes256_cbc_method, engine_aes256_cbc_do_cipher);
//     EVP_CIPHER_meth_set_cleanup(engine_aes256_cbc_method, engine_aes256_cbc_cleanup);
//     return engine_aes256_cbc_method;
// }

// /* chacha20 method */
// static EVP_CIPHER* engine_chacha20_method = NULL;
// static const EVP_CIPHER* init_engine_chacha20_method(void)
// {
//     printf("[Engine]: engine_chacha20_method called!\n");
//     engine_chacha20_method = EVP_CIPHER_meth_new(NID_chacha20, 8, 32);
//     EVP_CIPHER_meth_set_iv_length(engine_chacha20_method, 16);
//     EVP_CIPHER_meth_set_init(engine_chacha20_method, engine_chacha20_init);
//     EVP_CIPHER_meth_set_do_cipher(engine_chacha20_method, engine_chacha20_do_cipher);
//     EVP_CIPHER_meth_set_cleanup(engine_chacha20_method, engine_chacha20_cleanup);

//     return engine_chacha20_method;
// }

// /* cipher selector */ 
// static int cipher_ids[] = {NID_aes_256_cbc, NID_chacha20};
// static int engine_cipher_selector(ENGINE *e, const EVP_CIPHER **cipher, const int **nids, int nid)
// {
//     printf("[Engine]: engine_cipher_selector called!\n");
//     int ok = 1;

//     if (!cipher)
//     {
//         *nids = cipher_ids;
//         printf("[Engine]: \n Cipher is empty! Nid:%d\n", nid);
//         return 2;
//     }
    
//     switch (nid)
//     {
//         case NID_aes_256_cbc:
//             *cipher = init_engine_aes256_cbc_method();
//             break;
//         case NID_chacha20:
//             *cipher = init_engine_chacha20_method();
//             break;
//         default:
//             *cipher = NULL;
//             ok = 0;
//     }
//     return ok;
// }

     
// static int pkey_methods_ids[] = {NID_brainpoolP384r1};
// static int engine_pkey_selector(ENGINE *e, EVP_PKEY_METHOD **method,
//         const int **nids, int nid) {
    
//     printf("[Engine]: engine_digest_selector called!\n");
//     int ok = 1;

//     if (!method) {
//         *nids = pkey_methods_ids;
//         printf("[Engine]: \n Method is empty! Nid:%d\n", nid);
//         return 2;
//     }

//     switch (nid)
//     {
//         case NID_brainpoolP384r1:

//             printf("[Engine]: DigestSelector chose sha256\n");
//             *method = init_ecdh_method();
//             break;
//         default:
//             *method = NULL;
//             ok = 0;
//     }

//     return ok;
// }




/*
* This will be used to get the token / id of the private key
*/
// static int engine_ctrl_cmd_string(ENGINE* e, const char* cmd_name, const char* cmd_value)
// static int engine_ctrl_cmd_string(ENGINE* e, int cmd, long i, void* p, void (*f)(void))
// {
//     printf("[Engine]: engine_ctrl_cmd_string called!\n");
//     return 0;
// }


// static EVP_PKEY *engine_load_private_key(ENGINE *engine, const char *key_id,
//                               UI_METHOD *ui_method, void *callback_data) {
//     printf("[Engine]: engine_load_private_key called!\n");
//     return load_ec_key(key_id);
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





/* sha384 methods */
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





// /* aes 256 cbc methods */
// static inline int engine_aes256_cbc_init(EVP_CIPHER_CTX * ctx, const unsigned char *key,
// 		const unsigned char *iv, int enc)
// {
//     printf("[Engine]: engine_aes256_cbc_init called!\n");
//     return aes256_cbc_init(ctx, key, iv, enc); 
// }
 
// static inline int engine_aes256_cbc_do_cipher(EVP_CIPHER_CTX * ctx, unsigned char *out,
// 		const unsigned char *in, size_t inlen)
// {
//     printf("[Engine]: engine_aes256_cbc_do_cipher called!\n");
//     return aes256_cbc_do_cipher(ctx, out, in, inlen);
// }

// static inline int engine_aes256_cbc_cleanup(EVP_CIPHER_CTX *ctx)
// {
//     printf("[Engine]: engine_aes256_cbc_cleanup called!\n");
//     return aes256_cbc_cleanup(ctx); 
// }

// /* chacha20 methods */
// static inline int engine_chacha20_init(EVP_CIPHER_CTX * ctx, const unsigned char *key,
// 		const unsigned char *iv, int enc)
// {
//     printf("[Engine]: engine_chacha20_init called!\n");
//     return chacha20_init(ctx, key, iv, enc); 
// }
 
// static inline int engine_chacha20_do_cipher(EVP_CIPHER_CTX * ctx, unsigned char *out,
// 		const unsigned char *in, size_t inlen)
// {
//     printf("[Engine]: engine_chacha20_do_cipher called!\n");
//     return chacha20_do_cipher(ctx, out, in, inlen);
// }

// static inline int engine_chacha20_cleanup(EVP_CIPHER_CTX *ctx)
// {
//     printf("[Engine]: engine_chacha20_cleanup called!\n");
//     return chacha20_cleanup(ctx); 
// }




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
    memset(buffer,1,num);
    return 1;
}
