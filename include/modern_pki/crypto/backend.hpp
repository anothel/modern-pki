#pragma once

#include <string_view>

namespace modern_pki::crypto {

class Backend {
public:
    virtual ~Backend() = default;

    [[nodiscard]] virtual std::string_view name() const noexcept = 0;
};

}  // namespace modern_pki::crypto
