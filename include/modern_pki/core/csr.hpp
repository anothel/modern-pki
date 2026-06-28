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
	std::string public_key_algorithm;
	int public_key_size_bits = 0;
	std::string signature_algorithm;
};

[[nodiscard]] CsrInfo inspect_csr_pem(const std::string &csr_pem);

} // namespace modern_pki::core
