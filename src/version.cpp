#include "modern_pki/version.hpp"

namespace modern_pki {

Version library_version() noexcept
{
    return {0, 0, 0};
}

std::string_view library_version_string() noexcept
{
    return "0.0.0";
}

}  // namespace modern_pki
