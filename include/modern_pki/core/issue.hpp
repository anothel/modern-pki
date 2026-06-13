#pragma once

#include <string>
#include <vector>

namespace modern_pki::core
{

struct IssueRequest
{
	std::string csr_pem;
	std::string issuer_certificate_pem;
	std::string issuer_key_ref;
	std::string subject;
	std::vector<std::string> dns_names;
	std::vector<std::string> ip_addresses;
	std::string not_before;
	std::string not_after;
	std::string signature_algorithm;
};

struct IssueResult
{
	std::string certificate_pem;
	std::string serial_number;
	std::string subject;
	std::string not_before;
	std::string not_after;
};

[[nodiscard]] IssueResult issue_certificate(const IssueRequest &request);

} // namespace modern_pki::core
