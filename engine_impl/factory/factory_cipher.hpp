#ifndef ENGINE_IMPL_FACTORY_FACTORY_CIPHER_HPP
#define ENGINE_IMPL_FACTORY_FACTORY_CIPHER_HPP

#include <cstdint>
#include <openssl/evp.h>

namespace Factory {
/**
 * \brief An abstract base class for factory cipher implementations.
 *
 * This class provides a common interface for different cipher implementations
 * to be used within the Engine callback implementation.
 */
class FactoryCipher {
public:
  /**
   * \brief Returns the size of the implementation-specific context object.
   * \return The size of the implementation-specific context object in bytes.
   */
  virtual std::size_t ImplCtxSize() const noexcept = 0;

  /**
   * \brief Initializes the cipher context with the given key and initialization
   * vector (IV).
   * \pre The context pointer is valid and points to an allocated
   * memory area with at least ImplCtxSize() bytes of space.
   * \param ctx A pointer to the cipher context to initialize.
   * \param key A pointer to the key data.
   * \param iv A pointer to the initialization vector data.
   * \param enc A flag indicating whether the cipher should be used for
   * encryption (enc = 1) or decryption (enc = 0).
   * \return 1 on success, or 0 otherwise.
   */
  virtual int Init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                   const unsigned char *iv, int enc) noexcept = 0;

  /**
   * \brief Performs the cipher operation on the given input data.
   * \pre The context pointer is valid and has been initialized using Init().
   * \param ctx A pointer to the initialized cipher context.
   * \param out A pointer to the output buffer to store the encrypted/decrypted
   * data.
   * \param in A pointer to the input buffer containing the data to
   * encrypt/decrypt.
   * \param inlen The length of the input buffer in bytes.
   * \return The number of bytes written to the output buffer, or -1 on error.
   */
  virtual int DoCipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                       const unsigned char *in, size_t inlen) noexcept = 0;

  /**
   * \brief Cleans up the cipher context after use.
   * \pre The context pointer is valid and has been initialized and used using
   * Init() and DoCipher(), respectively.
   * \param ctx A pointer to the cipher context to clean up.
   * \return 1 on success, or 0 otherwise.
   */
  virtual int Cleanup(EVP_CIPHER_CTX *ctx) noexcept = 0;

  /**
   * \brief Provides additional control over the cipher context.
   * \pre The context pointer is valid and has been initialized and used using
   * Init() and DoCipher(), respectively.
   * \param ctx A pointer to the initialized cipher context.
   * \param type The type of control operation to perform.
   * \param arg An argument specific to the control operation.
   * \param ptr A pointer to additional data specific to the control operation.
   * \return The return value of the control operation, or -1 on error.
   */
  virtual int Ctrl(EVP_CIPHER_CTX *ctx, int type, int arg,
                   void *ptr) noexcept = 0;


  virtual std::unique_ptr<FactoryCipher> GetCipher(int nid) noexcept = 0;
  vritual std::unique_ptr<FactoryDigest> GetDigest(int nid) noexcept = 0;
};

} // namespace Factory

#endif // ENGINE_IMPL_FACTORY_FACTORY_CIPHER_HPP
