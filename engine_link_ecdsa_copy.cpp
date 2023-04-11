#include "engine_link.h"
#include <string>
#include <vector>

struct ecdsa_mapping
{
    EC_KEY* ec_key;
    ECDSA_SIG* sig;
    int type;
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_size;
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

    // set operation
    ecdsa_ctx->type = 1;

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

    // set operation
    ecdsa_ctx->type = 0;

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
        // cast to ECDSA_SIG
        ECDSA_SIG* sig_cast = d2i_ECDSA_SIG(nullptr, &sig, siglen);
        ok = ECDSA_do_verify(ecdsa_ctx->hash, ecdsa_ctx->hash_size, sig_cast, ecdsa_ctx->ec_key);
    }
    return ok;
}



int ecdsa_custom_digest_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    int ret = 0;

    // find the digest type
    const EVP_MD* type = EVP_MD_CTX_md(ctx);

    // get NID from type
    int nid = EVP_MD_type(type);

    // get alg from nid
    const EVP_MD* sw_type = EVP_get_digestbynid(nid);

    // create hash ctx
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();

    // init hash
    ret = EVP_DigestInit_ex(mdctx, sw_type, NULL);
    if (ret != 1)
    {
        return ret;
    }

    // update hash
    ret = EVP_DigestUpdate(mdctx, data, count);
    if (ret != 1)
    {
        return ret;
    }

    // finalize hash
    ret = EVP_DigestFinal_ex(mdctx, ecdsa_ctx->hash, &ecdsa_ctx->hash_size);
    if (ret != 1)
    {
        return ret;
    }

    // free
    EVP_MD_CTX_free(mdctx);

    // if EVP_PKEY is used for signing, issue the sign
    if (ecdsa_ctx->type == 1)
    {
        ecdsa_ctx->sig = ECDSA_do_sign(ecdsa_ctx->hash, (int)ecdsa_ctx->hash_size, ecdsa_ctx->ec_key);
    }
    

    return ret;
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
    // printf("ecdsa_ctrl called\n");
    // printf("Params: \n");
    // printf("ctx: %p, type: %d, p1: %d, p2: %p\n", ctx, type, p1, p2);
    
    return ok;
}



