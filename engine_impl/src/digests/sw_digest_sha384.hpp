#ifndef ENGINE_IMPL_FACTORY_SRC_DIGESTS_SW_DIGEST_SHA384_HPP
#define ENGINE_IMPL_FACTORY_SRC_DIGESTS_SW_DIGEST_SHA384_HPP

#include <factory/factory_digest.hpp>

namespace Factory {
namespace SoftwareImpl {

class SwSha384 : public FactoryDigest {
public:
  explicit SwSha384() = default;
  SwSha384(SwSha384 &) = delete;
  SwSha384(SwSha384 &&) = delete;
  SwSha384 &operator=(SwSha384 &) = delete;
  SwSha384 &operator=(SwSha384 &&) = delete;
  ~SwSha384() = default;

  std::size_t AppDataSize() const noexcept override;
  int Init(EVP_MD_CTX *ctx) noexcept override;
  int Update(EVP_MD_CTX *ctx, const void *in, size_t len) noexcept override;
  int Final(EVP_MD_CTX *ctx, unsigned char *md) noexcept override;
  int Cleanup(EVP_MD_CTX *ctx) noexcept override;

private:
    EVP_MD_CTX* ctx_;
};

} // namespace SoftwareImpl
} // namespace Factory

#endif // ENGINE_IMPL_FACTORY_SRC_DIGESTS_SW_DIGEST_SHA384_HPP
