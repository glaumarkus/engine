#ifndef ENGINE_IMPL_FACTORY_FACTORY_EC_HPP
#define ENGINE_IMPL_FACTORY_FACTORY_EC_HPP

#include <cstdint>
#include <openssl/evp.h>

namespace Factory {

/**
 * \brief The FactoryEC class is an interface to support
 * elliptic curve operations.
 */
class FactoryEC {
public:
  /**
   * \brief Initializes the key context.
   *
   * \param ctx The key context.
   * \return int Returns 1 on success and 0 on failure.
   */
  virtual int Init(EVP_PKEY_CTX *ctx) = 0;

  /**
   * \brief Cleans up the key context.
   *
   * \param ctx The key context.
   * \return int Returns 1 on success and 0 on failure.
   */
  virtual int Cleanup(EVP_PKEY_CTX *ctx) = 0;

  /**
   * \brief Initializes the signing operation.
   *
   * \param ctx The key context.
   * \param mctx The message digest context.
   * \return int Returns 1 on success and 0 on failure.
   */
  virtual int SignInit(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx) = 0;

  /**
   * \brief Performs the signing operation.
   *
   * \param ctx The key context.
   * \param sig The output buffer to store the signature.
   * \param siglen The length of the output buffer.
   * \param mctx The message digest context.
   * \return int Returns 1 on success and 0 on failure.
   */
  virtual int Sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                   EVP_MD_CTX *mctx) = 0;

  /**
   * \brief Initializes the signature verification operation.
   *
   * \param ctx The key context.
   * \param mctx The message digest context.
   * \return int Returns 1 on success and 0 on failure.
   */
  virtual int VerifyInit(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx) = 0;

  /**
   * \brief Performs the signature verification operation.
   *
   * \param ctx The key context.
   * \param sig The signature to verify.
   * \param siglen The length of the signature.
   * \param mctx The message digest context.
   * \return int Returns 1 on success and 0 on failure.
   */
  virtual int Verify(EVP_PKEY_CTX *ctx, const unsigned char *sig, int siglen,
                     EVP_MD_CTX *mctx) = 0;

  /**
   * \brief Initializes the custom digest operation.
   *
   * \param ctx The key context.
   * \param mctx The message digest context.
   * \return int Returns 1 on success and 0 on failure.
   */
  virtual int CustomDigest(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx) = 0;

  /**
   * \brief Initializes the key derivation operation.
   *
   * \param ctx The key context.
   * \return int Returns 1 on success and 0 on failure.
   */
  virtual int DeriveInit(EVP_PKEY_CTX *ctx) = 0;

  /**
   * \brief Performs the key derivation operation.
   *
   * \param ctx The key context.
   * \param key The output buffer to store the derived key.
   * \param keylen The length of the output buffer.
   * \return int Returns 1 on success and 0 on failure.
   */
  virtual int Derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen) = 0;

  /**
   * \brief Provides additional control over the cipher context.
   * \pre The context pointer is valid and has been initialized and used using
   * Init() and DoCipher(), respectively.
   * \param ctx A pointer to the initialized pkey context.
   * \param type The type of control operation to perform.
   * \param p1 An argument specific to the control operation.
   * \param ptr A pointer to additional data specific to the control operation.
   * \return The return value of the control operation, or -1 on error.
   */
  virtual int Ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2) = 0;
};

} // namespace Factory

#endif ENGINE_IMPL_FACTORY_FACTORY_EC_HPP
