#include "engine_link.h"
#include <string>
#include <vector>

struct ecdsa_mapping
{
    EC_KEY* ec_key;
    ECDSA_SIG* sig;
};

static ecdsa_mapping* ecdsa_ctx = nullptr;


/* ecdsa mapping */
int ecdsa_init(EVP_PKEY_CTX *ctx)
{
    ecdsa_ctx = new ecdsa_mapping;
    return 1;
}

int ecdsa_cleanup(EVP_PKEY_CTX *ctx)
{
    delete ecdsa_ctx;
    return 1;
}

int ecdsa_signctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx)
{
    if (ecdsa_ctx == nullptr)
    {
        ecdsa_init(ctx);
    }

    // cast key
    EVP_PKEY* pkey = EVP_PKEY_CTX_get0_pkey(ctx);
    ecdsa_ctx->ec_key = EVP_PKEY_get0_EC_KEY(pkey);

    // set flags
    EVP_MD_CTX_set_flags(mctx, EVP_MD_CTX_FLAG_FINALISE);
    return 1;
}

int ecdsa_verifyctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx)
{
    if (ecdsa_ctx == nullptr)
    {
        ecdsa_init(ctx);
    }

    // cast key
    EVP_PKEY* pkey = EVP_PKEY_CTX_get0_pkey(ctx);
    ecdsa_ctx->ec_key = EVP_PKEY_get0_EC_KEY(pkey);

    // set flags
    EVP_MD_CTX_set_flags(mctx, EVP_MD_CTX_FLAG_FINALISE);
    return 1;
}


int ecdsa_signctx(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, EVP_MD_CTX *mctx)
{
    int ok = 0;
    if (sig == nullptr)
    {
        int sig_len = i2d_ECDSA_SIG(ecdsa_ctx->sig, nullptr);
        *siglen = (size_t)sig_len;
        ok = 1;
    }
    else
    {
        int sig_len = i2d_ECDSA_SIG(ecdsa_ctx->sig, &sig);
        *siglen = (size_t)sig_len;
        ok = 1;
    }
    return ok;
}

int ecdsa_verifyctx(EVP_PKEY_CTX *ctx, const unsigned char *sig, int siglen, EVP_MD_CTX *mctx)
{
    int ok = 0;
    if (sig != nullptr)
    {

        // // ah damn, its not deterministic.. thats not going to work
        // unsigned char* sig_cpy = new unsigned char[EVP_PKEY_size(EVP_PKEY_CTX_get0_pkey(ctx))];
        // int sig_len = i2d_ECDSA_SIG(ecdsa_ctx->sig, &sig_cpy);
        // // check if size matches
        // if (sig_len != siglen)
        // {
        //     return ok;
        // }
    }
    return ok;
}



int ecdsa_custom_digest_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)data, count, hash);
    ecdsa_ctx->sig = ECDSA_do_sign(hash, SHA256_DIGEST_LENGTH, ecdsa_ctx->ec_key);
    return 1;
}

int ecdsa_custom_digest(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx)
{
    int ok = 0;
    if (ecdsa_ctx)
    {
        EVP_MD_CTX_set_update_fn(mctx, ecdsa_custom_digest_update);
        ok = 1;
    }
    
    return ok;
}



int ecdsa_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    int ok = 1;
    printf("ecdsa_ctrl called\n");
    printf("Params: \n");
    printf("ctx: %p, type: %d, p1: %d, p2: %p\n", ctx, type, p1, p2);
    
    return ok;
}



