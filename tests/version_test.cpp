#include "modern_pki/version.hpp"

#include <cassert>
#include <string_view>

int main()
{
    const auto version = modern_pki::library_version();

    assert(version.major == 0);
    assert(version.minor == 0);
    assert(version.patch == 0);
    assert(modern_pki::library_version_string() == std::string_view{"0.0.0"});

    return 0;
}
