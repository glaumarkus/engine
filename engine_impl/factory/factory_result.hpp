#ifndef ENGINE_IMPL_FACTORY_RESULT_HPP
#define ENGINE_IMPL_FACTORY_RESULT_HPP

#include <memory>

namespace engine {

template <typename T> class EngineResult {
public:
  EngineResult();

  T &Value() noexcept { return value_.get(); }

  bool HasValue() const noexcept { return value_ != nullptr; }

private:
  bool result_{false};
  std::unique_ptr<T> value_{nullptr};
};

} // namespace engine

#endif // ENGINE_IMPL_FACTORY_RESULT_HPP