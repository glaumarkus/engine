#include "engine_link.h"


struct sha256_digest_ctx {
	SHA256_CTX ctx;
};

/* sha256 mapping */
size_t sha256_size()
{
    return sizeof(sha256_digest_ctx);
}

int sha256_init(EVP_MD_CTX *ctx)
{
    auto digest_ctx = reinterpret_cast<sha256_digest_ctx*>(EVP_MD_CTX_md_data(ctx));
    return SHA256_Init(&digest_ctx->ctx);
}

int sha256_update(EVP_MD_CTX *ctx, const void *in, size_t len)
{
    auto digest_ctx = reinterpret_cast<sha256_digest_ctx*>(EVP_MD_CTX_md_data(ctx));
    return SHA256_Update(&digest_ctx->ctx, in, len);
}

int sha256_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    auto digest_ctx = reinterpret_cast<sha256_digest_ctx*>(EVP_MD_CTX_md_data(ctx));
    return SHA256_Final(md, &digest_ctx->ctx);
}

int sha256_cleanup(EVP_MD_CTX *ctx)
{
    return 1;
}


/* sha384 mapping */
struct sha384_digest_ctx {
    SHA512_CTX ctx;
};

size_t sha384_size()
{
    return sizeof(sha384_digest_ctx);
}

int sha384_init(EVP_MD_CTX *ctx)
{
    auto digest_ctx = reinterpret_cast<sha384_digest_ctx*>(EVP_MD_CTX_md_data(ctx));
    return SHA384_Init(&digest_ctx->ctx);
}

int sha384_update(EVP_MD_CTX *ctx, const void *in, size_t len)
{
    auto digest_ctx = reinterpret_cast<sha384_digest_ctx*>(EVP_MD_CTX_md_data(ctx));
    return SHA384_Update(&digest_ctx->ctx, in, len);
}

int sha384_final(EVP_MD_CTX *ctx, unsigned char *md)
{   
    auto digest_ctx = reinterpret_cast<sha384_digest_ctx*>(EVP_MD_CTX_md_data(ctx));
    return SHA384_Final(md, &digest_ctx->ctx);
}

int sha384_cleanup(EVP_MD_CTX *ctx)
{
    return 1;
}





// /* aes256 cbc mapping*/
// static EVP_CIPHER_CTX* aes_256_cbc_ctx = NULL;
// int aes256_cbc_init(EVP_CIPHER_CTX * ctx, const unsigned char *key, const unsigned char *iv, int enc)
// {
//     aes_256_cbc_ctx = EVP_CIPHER_CTX_new();
//     return EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
// }

// int aes256_cbc_do_cipher(EVP_CIPHER_CTX * ctx, unsigned char *out, const unsigned char *in, size_t inlen)
// {
//     int ciphertext_len = 0;
//     int final_len = 0;
//     int ret = 0;
//     ret = EVP_EncryptUpdate(ctx, out, &ciphertext_len, in, inlen);
//     if (ret != 1)
//     {
//         return ret;
//     }
//     ret = EVP_EncryptFinal_ex(ctx, out + ciphertext_len, &final_len);
//     return ret;
// }

// int aes256_cbc_cleanup(EVP_CIPHER_CTX *ctx)
// {
//     EVP_CIPHER_CTX_free(ctx);
//     return 1;
// }

// /* chacha20 mapping*/
// static EVP_CIPHER_CTX* chacha20_ctx = NULL;
// int chacha20_init(EVP_CIPHER_CTX * ctx, const unsigned char *key, const unsigned char *iv, int enc)
// {
//     chacha20_ctx = EVP_CIPHER_CTX_new();
//     return EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, key, iv);
// }

// int chacha20_do_cipher(EVP_CIPHER_CTX * ctx, unsigned char *out, const unsigned char *in, size_t inlen)
// {
//     int ciphertext_len = 0;
//     int final_len = 0;
//     int ret = 0;
//     ret = EVP_EncryptUpdate(ctx, out, &ciphertext_len, in, inlen);
//     if (ret != 1)
//     {
//         return ret;
//     }
//     ret = EVP_EncryptFinal_ex(ctx, out + ciphertext_len, &final_len);
//     return ret;
// }

// int chacha20_cleanup(EVP_CIPHER_CTX *ctx)
// {
//     EVP_CIPHER_CTX_free(ctx);
//     return 1;
// }




// EVP_PKEY* load_ec_key(const char* keyfile)
// {
//     FILE* fp = fopen(keyfile, "r");
//     if (!fp) {
//         printf("Error opening private key file\n");
//         return nullptr;
//     }

//     EVP_PKEY* pkey = nullptr;
//     EC_KEY* ec_key = nullptr;
//     ec_key = EC_KEY_new_by_curve_name(NID_brainpoolP384r1);

//     if (!ec_key) {
//         printf("Error creating EC_KEY object\n");
//         fclose(fp);
//         return nullptr;
//     }

//     if (!PEM_read_ECPrivateKey(fp, &ec_key, nullptr, nullptr)) {
//         printf("Error reading private key from file\n");
//         EC_KEY_free(ec_key);
//         fclose(fp);
//         return nullptr;
//     }

//     pkey = EVP_PKEY_new();
//     if (!pkey) {
//         printf("Error creating EVP_PKEY object\n");
//         EC_KEY_free(ec_key);
//         fclose(fp);
//         return nullptr;
//     }

//     if (!EVP_PKEY_set1_EC_KEY(pkey, ec_key)) {
//         printf("Error setting EC private key to EVP_PKEY object\n");
//         EVP_PKEY_free(pkey);
//         EC_KEY_free(ec_key);
//         fclose(fp);
//         return nullptr;
//     }

//     fclose(fp);
//     EC_KEY_free(ec_key);

//     return pkey;
// }