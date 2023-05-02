#ifndef ENGINE_IMPL_FACTORY_SRC_DIGESTS_SW_DIGEST_SHA256_HPP
#define ENGINE_IMPL_FACTORY_SRC_DIGESTS_SW_DIGEST_SHA256_HPP

#include <factory/factory_digest.hpp>

namespace Factory {
namespace SoftwareImpl {

class SwSha256 : public FactoryDigest {
public:
  explicit SwSha256() = default;
  SwSha256(SwSha256 &) = delete;
  SwSha256(SwSha256 &&) = delete;
  SwSha256 &operator=(SwSha256 &) = delete;
  SwSha256 &operator=(SwSha256 &&) = delete;
  ~SwSha256() = default;

  std::size_t AppDataSize() const noexcept override;
  int Init(EVP_MD_CTX *ctx) noexcept override;
  int Update(EVP_MD_CTX *ctx, const void *in, size_t len) noexcept override;
  int Final(EVP_MD_CTX *ctx, unsigned char *md) noexcept override;
  int Cleanup(EVP_MD_CTX *ctx) noexcept override;

private:
  EVP_MD_CTX *ctx_;
};

} // namespace SoftwareImpl
} // namespace Factory

#endif // ENGINE_IMPL_FACTORY_SRC_DIGESTS_SW_DIGEST_SHA256_HPP
