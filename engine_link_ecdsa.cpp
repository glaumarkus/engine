#include "engine_link.h"
#include <string>
#include <vector>

struct ecdsa_mapping
{
    EVP_MD_CTX* ctx;
    EVP_PKEY* pkey;
    const void *data; 
    size_t count;
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
    EVP_MD_CTX_free(ecdsa_ctx->ctx);
    delete ecdsa_ctx;
    return 1;
}


int ecdsa_signctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx)
{
    if (ecdsa_ctx == nullptr)
    {
        ecdsa_init(ctx);
    }
    ecdsa_ctx->ctx = EVP_MD_CTX_new();
    ecdsa_ctx->pkey = EVP_PKEY_CTX_get0_pkey(ctx);

    // set flags
    EVP_MD_CTX_set_flags(mctx, EVP_MD_CTX_FLAG_FINALISE);
    return 1;
}

int ecdsa_signctx(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, EVP_MD_CTX *mctx)
{
    return EVP_DigestSignFinal(mctx, sig, siglen);
}


int ecdsa_custom_digest_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    EVP_DigestSignUpdate(ctx, data, count);
    return 1;
}

int ecdsa_custom_digest(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx)
{
    int ok = 0;
    if (ecdsa_ctx)
    {
        // convert to sw
        const EVP_MD* alg = EVP_MD_CTX_md(mctx);
        int md_nid = EVP_MD_type(alg);
        const EVP_MD* mmd;
        if (md_nid == NID_sha256)
        {
            mmd = EVP_sha256();
        }
        else if (md_nid == NID_sha3_384)
        {
            mmd = EVP_sha3_256();
        }

        // replace ctx
        EVP_MD_CTX* swap = mctx;
        ecdsa_ctx->ctx = EVP_MD_CTX_new();
        mctx = ecdsa_ctx->ctx;
        ecdsa_ctx->ctx = swap;
        ok = EVP_DigestSignInit(mctx, nullptr, mmd, nullptr, ecdsa_ctx->pkey);
    }
    
    return ok;
}



// int ecdsa_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
// {
//     int ok = 1;
//     switch (type)
//     {
//         case 1:
//             break;
//         case 7:
//             break;
//         default:
//             ok = 0;
//             break;
//     }
//     return ok;
// }



// int ecdsa_signctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx)
// {
//     if (ecdsa_ctx == nullptr)
//     {
//         ecdsa_init(ctx);
//     }

//     ecdsa_ctx->ctx = EVP_MD_CTX_new();
//     ecdsa_ctx->pkey = EVP_PKEY_CTX_get0_pkey(ctx);
//     return 1;
// }

// int ecdsa_signctx(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, EVP_MD_CTX *mctx)
// {
//     int ret = EVP_DigestSignFinal(ecdsa_ctx->ctx, sig, siglen);
//     return ret;
// }


// int ecdsa_custom_digest_update(EVP_MD_CTX *ctx, const void *data, size_t count)
// {
//     ecdsa_ctx->data = data;
//     ecdsa_ctx->count = count;
//     // mine
//     EVP_DigestSignUpdate(ecdsa_ctx->ctx, data, count);
//     return 1;
// }

// int ecdsa_custom_digest(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx)
// {
//     int ok = 0;
//     if (ecdsa_ctx)
//     {
//         // find nid from digest
//         ok = EVP_DigestSignInit(ecdsa_ctx->ctx, nullptr, EVP_MD_CTX_md(mctx), nullptr, ecdsa_ctx->pkey);

//         // set update function for ctx
//         EVP_MD_CTX_set_update_fn(mctx, ecdsa_custom_digest_update);
//     }
    
//     return ok;
// }

