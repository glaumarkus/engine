#ifndef ENGINE_IMPL_FACTORY_FACTORY_DIGEST_HPP
#define ENGINE_IMPL_FACTORY_FACTORY_DIGEST_HPP

#include <cstdint>
#include <openssl/evp.h>

namespace Factory {

/**
 * \brief Abstract factory for creating digest objects
 */
class FactoryDigest {
public:
  /**
   * \brief Get the size of additional application data
   * \return std::size_t The size of additional application data
   */
  virtual std::size_t AppDataSize() const = 0;

  /**
   * \brief Initialize the digest context
   * \pre ctx != nullptr
   * \param ctx The digest context
   * \return int Zero on success, or a negative error code on failure
   */
  virtual int Init(EVP_MD_CTX *ctx) = 0;

  /**
   * \brief Update the digest context with new data
   * \pre ctx != nullptr
   * \pre in != nullptr
   * \param ctx The digest context
   * \param in Pointer to the input data
   * \param len Length of the input data in bytes
   * \return int Zero on success, or a negative error code on failure
   */
  virtual int Update(EVP_MD_CTX *ctx, const void *in, size_t len) = 0;

  /**
   * \brief Finalize the digest and output the resulting message digest value
   * \pre ctx != nullptr
   * \pre md != nullptr
   * \param ctx The digest context
   * \param md Pointer to the output buffer for the message digest value
   * \return int Zero on success, or a negative error code on failure
   */
  virtual int Final(EVP_MD_CTX *ctx, unsigned char *md) = 0;

  /**
   * \brief Cleanup the digest context
   * \pre ctx != nullptr
   * \param ctx The digest context
   * \return int Zero on success, or a negative error code on failure
   */
  virtual int Cleanup(EVP_MD_CTX *ctx) = 0;
};

} // namespace Factory

#endif ENGINE_IMPL_FACTORY_FACTORY_DIGEST_HPP
