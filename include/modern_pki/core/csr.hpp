#pragma once

#include <string>
#include <vector>

namespace modern_pki::core
{

struct CsrInfo
{
	std::string subject;
	std::vector<std::string> dns_names;
	std::vector<std::string> ip_addresses;
};

[[nodiscard]] CsrInfo inspect_csr_pem(const std::string &csr_pem);

} // namespace modern_pki::core
