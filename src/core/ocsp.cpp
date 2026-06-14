#include "modern_pki/core/ocsp.hpp"

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <cctype>
#include <fstream>
#include <iomanip>
#include <map>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>

namespace modern_pki::core
{
namespace
{

constexpr const char *kOCSPParseFailed = "ocsp.parse_failed";
constexpr const char *kOCSPCreateFailed = "ocsp.create_failed";
constexpr const char *kOCSPSignFailed = "ocsp.sign_failed";
constexpr const char *kOCSPIssuerParseFailed = "ocsp.issuer_parse_failed";
constexpr const char *kOCSPKeyReadFailed = "ocsp.key_read_failed";
constexpr const char *kOCSPInvalidTime = "ocsp.invalid_time";

template <typename T, void (*FreeFn)(T *)>
struct OpenSslDeleter
{
	void operator()(T *value) const noexcept
	{
		FreeFn(value);
	}
};

struct BioDeleter
{
	void operator()(BIO *bio) const noexcept
	{
		BIO_free(bio);
	}
};

using Asn1TimePtr = std::unique_ptr<ASN1_TIME, OpenSslDeleter<ASN1_TIME, ASN1_TIME_free>>;
using BignumPtr = std::unique_ptr<BIGNUM, OpenSslDeleter<BIGNUM, BN_free>>;
using BioPtr = std::unique_ptr<BIO, BioDeleter>;
using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, OpenSslDeleter<EVP_PKEY, EVP_PKEY_free>>;
using OCSPBasicResponsePtr = std::unique_ptr<OCSP_BASICRESP, OpenSslDeleter<OCSP_BASICRESP, OCSP_BASICRESP_free>>;
using OCSPCertIDPtr = std::unique_ptr<OCSP_CERTID, OpenSslDeleter<OCSP_CERTID, OCSP_CERTID_free>>;
using OCSPRequestPtr = std::unique_ptr<OCSP_REQUEST, OpenSslDeleter<OCSP_REQUEST, OCSP_REQUEST_free>>;
using OCSPResponsePtr = std::unique_ptr<OCSP_RESPONSE, OpenSslDeleter<OCSP_RESPONSE, OCSP_RESPONSE_free>>;
using X509Ptr = std::unique_ptr<X509, OpenSslDeleter<X509, X509_free>>;

[[noreturn]] void throw_error(const char *code)
{
	throw std::runtime_error{code};
}

std::string read_file(const std::string &path)
{
	std::ifstream input{path, std::ios::binary};
	if (!input)
	{
		throw_error(kOCSPKeyReadFailed);
	}
	std::string contents{std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{}};
	if (input.bad())
	{
		throw_error(kOCSPKeyReadFailed);
	}
	return contents;
}

X509Ptr parse_certificate(std::string_view pem)
{
	BioPtr bio{BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()))};
	if (!bio)
	{
		throw_error(kOCSPIssuerParseFailed);
	}
	X509Ptr certificate{PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr)};
	if (!certificate)
	{
		throw_error(kOCSPIssuerParseFailed);
	}
	return certificate;
}

EvpPkeyPtr parse_private_key(std::string_view pem)
{
	BioPtr bio{BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()))};
	if (!bio)
	{
		throw_error(kOCSPKeyReadFailed);
	}
	EvpPkeyPtr key{PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr)};
	if (!key)
	{
		throw_error(kOCSPKeyReadFailed);
	}
	return key;
}

OCSPRequestPtr parse_request_der(const std::string &der)
{
	BioPtr bio{BIO_new_mem_buf(der.data(), static_cast<int>(der.size()))};
	if (!bio)
	{
		throw_error(kOCSPParseFailed);
	}
	OCSPRequestPtr request{d2i_OCSP_REQUEST_bio(bio.get(), nullptr)};
	if (!request)
	{
		throw_error(kOCSPParseFailed);
	}
	return request;
}

std::string octets_to_hex(const ASN1_OCTET_STRING *value)
{
	if (value == nullptr)
	{
		throw_error(kOCSPParseFailed);
	}
	std::ostringstream output;
	output << std::hex << std::setfill('0');
	for (int index = 0; index < value->length; ++index)
	{
		output << std::setw(2) << static_cast<int>(value->data[index]);
	}
	return output.str();
}

std::string serial_to_decimal(const ASN1_INTEGER *serial)
{
	if (serial == nullptr)
	{
		throw_error(kOCSPParseFailed);
	}
	BIGNUM *raw = ASN1_INTEGER_to_BN(serial, nullptr);
	if (raw == nullptr)
	{
		throw_error(kOCSPParseFailed);
	}
	BignumPtr serial_bn{raw};
	char *decimal_raw = BN_bn2dec(serial_bn.get());
	if (decimal_raw == nullptr)
	{
		throw_error(kOCSPParseFailed);
	}
	std::string decimal{decimal_raw};
	OPENSSL_free(decimal_raw);
	return decimal;
}

OCSPCertificateID certificate_id(OCSP_CERTID *id)
{
	ASN1_OCTET_STRING *issuer_name_hash = nullptr;
	ASN1_OCTET_STRING *issuer_key_hash = nullptr;
	ASN1_INTEGER *serial = nullptr;
	if (OCSP_id_get0_info(&issuer_name_hash, nullptr, &issuer_key_hash, &serial, id) != 1)
	{
		throw_error(kOCSPParseFailed);
	}
	return OCSPCertificateID{
	    serial_to_decimal(serial),
	    octets_to_hex(issuer_name_hash),
	    octets_to_hex(issuer_key_hash),
	};
}

std::string asn1_time_from_rfc3339(std::string_view value)
{
	if (value.size() != 20 || value[4] != '-' || value[7] != '-' || value[10] != 'T' || value[13] != ':' ||
	    value[16] != ':' || value[19] != 'Z')
	{
		throw_error(kOCSPInvalidTime);
	}
	return std::string{value.substr(0, 4)} + std::string{value.substr(5, 2)} + std::string{value.substr(8, 2)} +
	       std::string{value.substr(11, 2)} + std::string{value.substr(14, 2)} + std::string{value.substr(17, 2)} + "Z";
}

Asn1TimePtr make_time(std::string_view value)
{
	Asn1TimePtr time{ASN1_TIME_new()};
	if (!time)
	{
		throw_error(kOCSPCreateFailed);
	}
	const std::string asn1_time = asn1_time_from_rfc3339(value);
	if (ASN1_TIME_set_string(time.get(), asn1_time.c_str()) != 1)
	{
		throw_error(kOCSPInvalidTime);
	}
	return time;
}

int ocsp_status(std::string_view status)
{
	if (status == "good")
	{
		return V_OCSP_CERTSTATUS_GOOD;
	}
	if (status == "revoked")
	{
		return V_OCSP_CERTSTATUS_REVOKED;
	}
	if (status == "unknown")
	{
		return V_OCSP_CERTSTATUS_UNKNOWN;
	}
	throw_error(kOCSPCreateFailed);
}

int ocsp_revocation_reason(std::string_view reason)
{
	if (reason == "key_compromise")
	{
		return OCSP_REVOKED_STATUS_KEYCOMPROMISE;
	}
	if (reason == "ca_compromise")
	{
		return OCSP_REVOKED_STATUS_CACOMPROMISE;
	}
	if (reason == "affiliation_changed")
	{
		return OCSP_REVOKED_STATUS_AFFILIATIONCHANGED;
	}
	if (reason == "superseded")
	{
		return OCSP_REVOKED_STATUS_SUPERSEDED;
	}
	if (reason == "cessation_of_operation")
	{
		return OCSP_REVOKED_STATUS_CESSATIONOFOPERATION;
	}
	if (reason == "privilege_withdrawn")
	{
		return OCSP_REVOKED_STATUS_PRIVILEGEWITHDRAWN;
	}
	return OCSP_REVOKED_STATUS_UNSPECIFIED;
}

std::map<std::string, OCSPCertificateStatus> statuses_by_serial(const std::vector<OCSPCertificateStatus> &statuses)
{
	std::map<std::string, OCSPCertificateStatus> by_serial;
	for (const OCSPCertificateStatus &status : statuses)
	{
		by_serial[status.serial_number] = status;
	}
	return by_serial;
}

std::string response_to_der(OCSP_RESPONSE *response)
{
	BioPtr bio{BIO_new(BIO_s_mem())};
	if (!bio || i2d_OCSP_RESPONSE_bio(bio.get(), response) != 1)
	{
		throw_error(kOCSPCreateFailed);
	}
	char *data = nullptr;
	const long size = BIO_get_mem_data(bio.get(), &data);
	if (size <= 0 || data == nullptr)
	{
		throw_error(kOCSPCreateFailed);
	}
	return std::string{data, static_cast<std::string::size_type>(size)};
}

} // namespace

OCSPRequestInfo inspect_ocsp_request_der(const std::string &request_der)
{
	const OCSPRequestPtr request = parse_request_der(request_der);
	OCSPRequestInfo info;
	const int count = OCSP_request_onereq_count(request.get());
	for (int index = 0; index < count; ++index)
	{
		OCSP_ONEREQ *one = OCSP_request_onereq_get0(request.get(), index);
		if (one == nullptr)
		{
			throw_error(kOCSPParseFailed);
		}
		info.certificates.push_back(certificate_id(OCSP_onereq_get0_id(one)));
	}
	return info;
}

GenerateOCSPResponseResult generate_ocsp_response(const GenerateOCSPResponseRequest &request)
{
	const OCSPRequestPtr ocsp_request = parse_request_der(request.request_der);
	const X509Ptr issuer = parse_certificate(request.issuer_certificate_pem);
	const EvpPkeyPtr issuer_key = parse_private_key(read_file(request.issuer_key_ref));
	const Asn1TimePtr this_update = make_time(request.this_update);
	const Asn1TimePtr next_update = make_time(request.next_update);
	const std::map<std::string, OCSPCertificateStatus> statuses = statuses_by_serial(request.certificates);

	OCSPBasicResponsePtr basic{OCSP_BASICRESP_new()};
	if (!basic)
	{
		throw_error(kOCSPCreateFailed);
	}

	const int count = OCSP_request_onereq_count(ocsp_request.get());
	for (int index = 0; index < count; ++index)
	{
		OCSP_ONEREQ *one = OCSP_request_onereq_get0(ocsp_request.get(), index);
		if (one == nullptr)
		{
			throw_error(kOCSPParseFailed);
		}
		OCSP_CERTID *id = OCSP_onereq_get0_id(one);
		const OCSPCertificateID parsed_id = certificate_id(id);
		const auto found = statuses.find(parsed_id.serial_number);
		const OCSPCertificateStatus status =
		    found == statuses.end() ? OCSPCertificateStatus{parsed_id.serial_number, "unknown", {}, {}} : found->second;
		Asn1TimePtr revoked_at;
		ASN1_TIME *revoked_at_raw = nullptr;
		int reason = OCSP_REVOKED_STATUS_NOSTATUS;
		if (status.status == "revoked")
		{
			revoked_at = make_time(status.revoked_at);
			revoked_at_raw = revoked_at.get();
			reason = ocsp_revocation_reason(status.revocation_reason);
		}
		if (OCSP_basic_add1_status(
		        basic.get(),
		        id,
		        ocsp_status(status.status),
		        reason,
		        revoked_at_raw,
		        this_update.get(),
		        next_update.get()) == nullptr)
		{
			throw_error(kOCSPCreateFailed);
		}
	}

	if (OCSP_basic_sign(basic.get(), issuer.get(), issuer_key.get(), EVP_sha256(), nullptr, 0) != 1)
	{
		throw_error(kOCSPSignFailed);
	}
	OCSPResponsePtr response{OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, basic.get())};
	if (!response)
	{
		throw_error(kOCSPCreateFailed);
	}
	return GenerateOCSPResponseResult{response_to_der(response.get())};
}

} // namespace modern_pki::core
