#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace modern_pki::core
{

struct RevokedCertificate
{
	std::string serial_number;
	std::string revoked_at;
	std::string reason;
};

struct GenerateCRLRequest
{
	std::string issuer_certificate_pem;
	std::string issuer_key_ref;
	std::int64_t crl_number = 0;
	std::string this_update;
	std::string next_update;
	std::vector<RevokedCertificate> revoked_certificates;
};

struct GenerateCRLResult
{
	std::string crl_pem;
};

[[nodiscard]] GenerateCRLResult generate_crl(const GenerateCRLRequest &request);

} // namespace modern_pki::core
