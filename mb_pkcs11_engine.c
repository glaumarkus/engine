#include <openssl/evp.h>
#include <string.h>
#include <openssl/engine.h>
#include <openssl/ossl_typ.h>
#include <openssl/sha.h>

static const char *mb_engine_id = "MB_PKCS11_ENGINE";
static const char *mb_engine_name = "MB.OS custom PKCS11 Engine";


/*
* Return the state of the random engine machine, since using the PSC we would indicate positive return
*/
static int engine_random_status(void)
{
    printf("engine_random_status called\n");
    return 1;
}

/*
* TRNG function to receive bytes, check on NV hsm if there is a minimun entropy that is required
*/
static int engine_get_random_bytes(unsigned char *buffer, int num) {
    printf("engine_get_random_bytes called for %d bytes\n", num);
    memset(buffer,1,num);
    return 1;
}

/*
* Random Structure from OpenSSL
*/
RAND_METHOD engine_random_method = {
        NULL,                       /* seed */
        engine_get_random_bytes,    /* bytes */
        NULL,                       /* cleanup */
        NULL,                       /* add */
        NULL,                       /* pseudorand */
        engine_random_status        /* status */
};



/*
* enum for hashing algorithms
*/
enum alg_type { alg_sha256 };


/*
* struct for digest
*/
struct digest_ctx {
	SHA256_CTX ctx;
};




/*
* SHA256 Mapping
*/
static inline int engine_sha256_init(EVP_MD_CTX *ctx);
static inline int engine_sha256_update(EVP_MD_CTX *ctx, const void *in, size_t len);
static inline int engine_sha256_final(EVP_MD_CTX *ctx, unsigned char *md);
static inline int engine_sha256_copy(EVP_MD_CTX *dst, const EVP_MD_CTX *src);
static inline int engine_sha256_cleanup(EVP_MD_CTX *ctx);

/*
* Method mapping
*/
static EVP_MD* engine_sha256_method = NULL;
static const EVP_MD* init_engine_sha256_method(void)
{
    printf("init_engine_sha256_method called\n");
    // init new method
    engine_sha256_method = EVP_MD_meth_new(NID_sha256, NID_undef);
    EVP_MD_meth_set_result_size(engine_sha256_method, 32);
    EVP_MD_meth_set_input_blocksize(engine_sha256_method, 64);
    EVP_MD_meth_set_app_datasize(engine_sha256_method, sizeof(struct digest_ctx)); 

    // set functions
    EVP_MD_meth_set_init(engine_sha256_method, engine_sha256_init);
    EVP_MD_meth_set_update(engine_sha256_method, engine_sha256_update);
    EVP_MD_meth_set_final(engine_sha256_method, engine_sha256_final);
    EVP_MD_meth_set_copy(engine_sha256_method, engine_sha256_copy);
    EVP_MD_meth_set_cleanup(engine_sha256_method, engine_sha256_cleanup);

    return engine_sha256_method;
}

// cast to ctx
#define CTX_CAST(ctx) ((struct digest_ctx *)(EVP_MD_CTX_md_data(ctx)))

static inline int engine_sha256_init(EVP_MD_CTX *ctx)
{
    printf("engine_sha256_init called!\n");
    return 1;
}

static inline int engine_sha256_update(EVP_MD_CTX *ctx, const void *in, size_t len)
{
    printf("engine_sha256_update called!\n");
    return 1;
}

static inline int engine_sha256_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    printf("engine_sha256_final called!\n");
    return 1;
}

static inline int engine_sha256_copy(EVP_MD_CTX *dst, const EVP_MD_CTX *src)
{
    printf("engine_sha256_copy called!\n");
    return 1;
}

static inline int engine_sha256_cleanup(EVP_MD_CTX *ctx)
{
    printf("engine_sha256_cleanup called!\n");
    return 1;
}




/* 
* Collection of digest ids
*/
static int digest_ids[] = {NID_sha256};

/*
* Digest selector
*/
static int engine_digest_selector(ENGINE *e, const EVP_MD **digest,
        const int **nids, int nid) {
    
    printf("engine_digest_selector called!\n");
    int ok = 1;

    if (!digest) {
        *nids = digest_ids;
        printf("\n Digest is empty! Nid:%d\n", nid);
        return 2;
    }

    switch (nid)
    {
        case NID_sha256:

            printf("DigestSelector chose sha256\n");
            *digest = init_engine_sha256_method();
            break;
        default:
            *digest = NULL;
            ok = 0;
    }

    return ok;
}






static int engine_init(ENGINE* engine)
{
    printf("engine_init called\n");
    return 1;
}

static int engine_finish(ENGINE* engine)
{
    printf("engine_finish called\n");
    return 1;
}


/*
* This will be used to get the token / id of the private key
*/
static int engine_ctrl_cmd_string(ENGINE* e, const char* cmd_name, const char* cmd_value)
{
    if (strcmp(cmd_name, "CURLOPT_SSLKEY") == 0)
    {
        // Parse the PKCS11 URI string
        char token_name[64], object_name[64];
        if (sscanf(cmd_value, "pkcs11:token=%63[^;];object=%63s", token_name, object_name) != 2)
        {
            return 0;
        }
    }

    // Handle any other options here

    return 0;
}


/*
* This gets called when the engine is bound from another program
*/
int engine_bind(ENGINE * e, const char *id)
{
    printf("engine_bind called\n");
    if (!ENGINE_set_id(e, mb_engine_id) ||
        !ENGINE_set_name(e, mb_engine_name) ||
        !ENGINE_set_ctrl_function(e, engine_ctrl_cmd_string) ||
        !ENGINE_set_init_function(e, engine_init) ||
        !ENGINE_set_finish_function(e, engine_finish) ||
        !ENGINE_set_RAND(e, &engine_random_method) ||
        !ENGINE_set_digests(e, &engine_digest_selector)
                )
        return 0;
    return 1;
}


IMPLEMENT_DYNAMIC_BIND_FN(engine_bind)
IMPLEMENT_DYNAMIC_CHECK_FN()
