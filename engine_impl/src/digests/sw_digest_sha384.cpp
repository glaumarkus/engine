#include "sw_digest_sha384.hpp"

namespace Factory {
namespace SoftwareImpl {


std::size_t SwSha384::AppDataSize() const noexcept 
{
    return sizeof(SwSha384);
}

int SwSha384::Init(EVP_MD_CTX *ctx) noexcept {
    ctx_ = EVP_MD_CTX_create();
    // initialize the ctx
    return EVP_DigestInit_ex(ctx_, EVP_sha384(), nullptr);
}

int SwSha384::Update(EVP_MD_CTX *ctx, const void *in, size_t len) noexcept {
    // update the ctx
    return EVP_DigestUpdate(ctx_, in, len);
}
int SwSha384::Final(EVP_MD_CTX *ctx, unsigned char *md) noexcept {
    // finalize the ctx
    unsigned int len = 0;
    return EVP_DigestFinal_ex(ctx_, md, &len);
}
int SwSha384::Cleanup(EVP_MD_CTX *ctx) noexcept {
    EVP_MD_CTX_free(ctx_);
    return 1;
}


} // namespace SoftwareImpl
} // namespace Factory
