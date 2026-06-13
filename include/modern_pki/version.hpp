#pragma once

#include <string_view>

namespace modern_pki {

struct Version {
    int major;
    int minor;
    int patch;
};

[[nodiscard]] Version library_version() noexcept;
[[nodiscard]] std::string_view library_version_string() noexcept;

}  // namespace modern_pki
