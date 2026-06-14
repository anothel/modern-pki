#include "modern_pki/core/ocsp.hpp"

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>

namespace
{

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

using BioPtr = std::unique_ptr<BIO, BioDeleter>;
using BignumPtr = std::unique_ptr<BIGNUM, OpenSslDeleter<BIGNUM, BN_free>>;
using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, OpenSslDeleter<EVP_PKEY, EVP_PKEY_free>>;
using EvpPkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, OpenSslDeleter<EVP_PKEY_CTX, EVP_PKEY_CTX_free>>;
using OCSPCertIDPtr = std::unique_ptr<OCSP_CERTID, OpenSslDeleter<OCSP_CERTID, OCSP_CERTID_free>>;
using OCSPRequestPtr = std::unique_ptr<OCSP_REQUEST, OpenSslDeleter<OCSP_REQUEST, OCSP_REQUEST_free>>;
using OCSPResponsePtr = std::unique_ptr<OCSP_RESPONSE, OpenSslDeleter<OCSP_RESPONSE, OCSP_RESPONSE_free>>;
using OCSPBasicResponsePtr = std::unique_ptr<OCSP_BASICRESP, OpenSslDeleter<OCSP_BASICRESP, OCSP_BASICRESP_free>>;
using X509Ptr = std::unique_ptr<X509, OpenSslDeleter<X509, X509_free>>;

void require(bool condition)
{
	if (!condition)
	{
		std::abort();
	}
}

EvpPkeyPtr make_rsa_key()
{
	EvpPkeyCtxPtr context{EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr)};
	require(context != nullptr);
	require(EVP_PKEY_keygen_init(context.get()) == 1);
	require(EVP_PKEY_CTX_set_rsa_keygen_bits(context.get(), 2048) == 1);
	EVP_PKEY *key = nullptr;
	require(EVP_PKEY_keygen(context.get(), &key) == 1);
	return EvpPkeyPtr{key};
}

void set_name(X509_NAME *name, const char *common_name)
{
	require(X509_NAME_add_entry_by_txt(
	            name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char *>(common_name), -1, -1, 0) == 1);
}

void set_serial(X509 *certificate, unsigned long serial)
{
	BignumPtr serial_bn{BN_new()};
	require(serial_bn != nullptr);
	require(BN_set_word(serial_bn.get(), serial) == 1);
	require(BN_to_ASN1_INTEGER(serial_bn.get(), X509_get_serialNumber(certificate)) != nullptr);
}

void add_extension(X509 *certificate, X509 *issuer, int nid, const char *value)
{
	X509V3_CTX context{};
	X509V3_set_ctx_nodb(&context);
	X509V3_set_ctx(&context, issuer, certificate, nullptr, nullptr, 0);
	X509_EXTENSION *extension = X509V3_EXT_conf_nid(nullptr, &context, nid, value);
	require(extension != nullptr);
	require(X509_add_ext(certificate, extension, -1) == 1);
	X509_EXTENSION_free(extension);
}

X509Ptr make_certificate(EVP_PKEY *key, X509 *issuer, EVP_PKEY *issuer_key, const char *common_name, unsigned long serial, bool ca)
{
	X509Ptr certificate{X509_new()};
	require(certificate != nullptr);
	require(X509_set_version(certificate.get(), 2) == 1);
	set_serial(certificate.get(), serial);
	X509_gmtime_adj(X509_getm_notBefore(certificate.get()), 0);
	X509_gmtime_adj(X509_getm_notAfter(certificate.get()), 86400);
	set_name(X509_get_subject_name(certificate.get()), common_name);
	require(X509_set_issuer_name(certificate.get(), issuer == nullptr ? X509_get_subject_name(certificate.get()) : X509_get_subject_name(issuer)) == 1);
	require(X509_set_pubkey(certificate.get(), key) == 1);
	if (ca)
	{
		add_extension(certificate.get(), certificate.get(), NID_basic_constraints, "critical,CA:TRUE");
		add_extension(certificate.get(), certificate.get(), NID_key_usage, "critical,keyCertSign,cRLSign");
	}
	require(X509_sign(certificate.get(), issuer_key == nullptr ? key : issuer_key, EVP_sha256()) > 0);
	return certificate;
}

std::string certificate_to_pem(X509 *certificate)
{
	BioPtr bio{BIO_new(BIO_s_mem())};
	require(bio != nullptr);
	require(PEM_write_bio_X509(bio.get(), certificate) == 1);
	char *data = nullptr;
	const long size = BIO_get_mem_data(bio.get(), &data);
	require(size > 0 && data != nullptr);
	return std::string{data, static_cast<std::string::size_type>(size)};
}

std::string private_key_to_pem(EVP_PKEY *key)
{
	BioPtr bio{BIO_new(BIO_s_mem())};
	require(bio != nullptr);
	require(PEM_write_bio_PrivateKey(bio.get(), key, nullptr, nullptr, 0, nullptr, nullptr) == 1);
	char *data = nullptr;
	const long size = BIO_get_mem_data(bio.get(), &data);
	require(size > 0 && data != nullptr);
	return std::string{data, static_cast<std::string::size_type>(size)};
}

std::string ocsp_request_der(X509 *leaf, X509 *issuer, OCSP_CERTID **out_id)
{
	OCSPRequestPtr request{OCSP_REQUEST_new()};
	require(request != nullptr);
	OCSP_CERTID *id = OCSP_cert_to_id(EVP_sha1(), leaf, issuer);
	require(id != nullptr);
	*out_id = OCSP_CERTID_dup(id);
	require(*out_id != nullptr);
	require(OCSP_request_add0_id(request.get(), id) != nullptr);
	BioPtr bio{BIO_new(BIO_s_mem())};
	require(bio != nullptr);
	require(i2d_OCSP_REQUEST_bio(bio.get(), request.get()) == 1);
	char *data = nullptr;
	const long size = BIO_get_mem_data(bio.get(), &data);
	require(size > 0 && data != nullptr);
	return std::string{data, static_cast<std::string::size_type>(size)};
}

void write_file(const std::filesystem::path &path, const std::string &contents)
{
	std::ofstream output{path, std::ios::binary | std::ios::trunc};
	output << contents;
}

OCSPResponsePtr ocsp_response_from_der(const std::string &der)
{
	BioPtr bio{BIO_new_mem_buf(der.data(), static_cast<int>(der.size()))};
	require(bio != nullptr);
	OCSPResponsePtr response{d2i_OCSP_RESPONSE_bio(bio.get(), nullptr)};
	require(response != nullptr);
	return response;
}

} // namespace

int main(int argc, char *argv[])
{
	require(argc == 2);
	const std::filesystem::path work_dir = argv[1];
	const EvpPkeyPtr issuer_key = make_rsa_key();
	const X509Ptr issuer = make_certificate(issuer_key.get(), nullptr, nullptr, "Test CA", 1, true);
	const EvpPkeyPtr leaf_key = make_rsa_key();
	const X509Ptr leaf = make_certificate(leaf_key.get(), issuer.get(), issuer_key.get(), "Leaf", 1001, false);
	const std::filesystem::path issuer_key_path = work_dir / "core_ocsp_issuer.key";
	write_file(issuer_key_path, private_key_to_pem(issuer_key.get()));

	OCSP_CERTID *raw_id = nullptr;
	const std::string request_der = ocsp_request_der(leaf.get(), issuer.get(), &raw_id);
	OCSPCertIDPtr id{raw_id};

	const modern_pki::core::OCSPRequestInfo info = modern_pki::core::inspect_ocsp_request_der(request_der);
	require(info.certificates.size() == 1);
	require(info.certificates[0].serial_number == "1001");
	require(!info.certificates[0].issuer_name_hash.empty());
	require(!info.certificates[0].issuer_key_hash.empty());

	modern_pki::core::GenerateOCSPResponseRequest response_request;
	response_request.request_der = request_der;
	response_request.issuer_certificate_pem = certificate_to_pem(issuer.get());
	response_request.issuer_key_ref = issuer_key_path.string();
	response_request.this_update = "2026-06-13T00:00:00Z";
	response_request.next_update = "2026-06-14T00:00:00Z";
	response_request.certificates.push_back({"1001", "revoked", "2026-06-13T01:00:00Z", "key_compromise"});

	const modern_pki::core::GenerateOCSPResponseResult response_result = modern_pki::core::generate_ocsp_response(response_request);
	const OCSPResponsePtr response = ocsp_response_from_der(response_result.response_der);
	require(OCSP_response_status(response.get()) == OCSP_RESPONSE_STATUS_SUCCESSFUL);
	OCSPBasicResponsePtr basic{OCSP_response_get1_basic(response.get())};
	require(basic != nullptr);
	int status = -1;
	int reason = -1;
	ASN1_GENERALIZEDTIME *revocation_time = nullptr;
	ASN1_GENERALIZEDTIME *this_update = nullptr;
	ASN1_GENERALIZEDTIME *next_update = nullptr;
	require(OCSP_resp_find_status(basic.get(), id.get(), &status, &reason, &revocation_time, &this_update, &next_update) == 1);
	require(status == V_OCSP_CERTSTATUS_REVOKED);
	require(reason == OCSP_REVOKED_STATUS_KEYCOMPROMISE);
	return 0;
}
