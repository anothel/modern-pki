#include "modern_pki/core/issue.hpp"

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <cassert>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>

namespace
{

struct BioDeleter
{
	void operator()(BIO *bio) const noexcept
	{
		BIO_free(bio);
	}
};

struct BignumDeleter
{
	void operator()(BIGNUM *value) const noexcept
	{
		BN_free(value);
	}
};

struct EvpPkeyDeleter
{
	void operator()(EVP_PKEY *key) const noexcept
	{
		EVP_PKEY_free(key);
	}
};

struct EvpPkeyCtxDeleter
{
	void operator()(EVP_PKEY_CTX *context) const noexcept
	{
		EVP_PKEY_CTX_free(context);
	}
};

struct X509Deleter
{
	void operator()(X509 *certificate) const noexcept
	{
		X509_free(certificate);
	}
};

struct X509ReqDeleter
{
	void operator()(X509_REQ *request) const noexcept
	{
		X509_REQ_free(request);
	}
};

struct Asn1BitStringDeleter
{
	void operator()(ASN1_BIT_STRING *value) const noexcept
	{
		ASN1_BIT_STRING_free(value);
	}
};

struct BasicConstraintsDeleter
{
	void operator()(BASIC_CONSTRAINTS *value) const noexcept
	{
		BASIC_CONSTRAINTS_free(value);
	}
};

struct ExtendedKeyUsageDeleter
{
	void operator()(EXTENDED_KEY_USAGE *value) const noexcept
	{
		sk_ASN1_OBJECT_pop_free(value, ASN1_OBJECT_free);
	}
};

using BioPtr = std::unique_ptr<BIO, BioDeleter>;
using BignumPtr = std::unique_ptr<BIGNUM, BignumDeleter>;
using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;
using EvpPkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter>;
using X509Ptr = std::unique_ptr<X509, X509Deleter>;
using X509ReqPtr = std::unique_ptr<X509_REQ, X509ReqDeleter>;
using Asn1BitStringPtr = std::unique_ptr<ASN1_BIT_STRING, Asn1BitStringDeleter>;
using BasicConstraintsPtr = std::unique_ptr<BASIC_CONSTRAINTS, BasicConstraintsDeleter>;
using ExtendedKeyUsagePtr = std::unique_ptr<EXTENDED_KEY_USAGE, ExtendedKeyUsageDeleter>;

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
	require(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char *>(common_name), -1, -1, 0) == 1);
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

std::string csr_to_pem(X509_REQ *request)
{
	BioPtr bio{BIO_new(BIO_s_mem())};
	require(bio != nullptr);
	require(PEM_write_bio_X509_REQ(bio.get(), request) == 1);
	char *data = nullptr;
	const long size = BIO_get_mem_data(bio.get(), &data);
	require(size > 0 && data != nullptr);
	return std::string{data, static_cast<std::string::size_type>(size)};
}

X509Ptr certificate_from_pem(const std::string &pem)
{
	BioPtr bio{BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()))};
	require(bio != nullptr);
	X509Ptr certificate{PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr)};
	require(certificate != nullptr);
	return certificate;
}

X509Ptr make_ca_certificate(EVP_PKEY *key)
{
	X509Ptr certificate{X509_new()};
	require(certificate != nullptr);
	require(X509_set_version(certificate.get(), 2) == 1);
	BignumPtr serial{BN_new()};
	require(serial != nullptr);
	require(BN_set_word(serial.get(), 1) == 1);
	require(BN_to_ASN1_INTEGER(serial.get(), X509_get_serialNumber(certificate.get())) != nullptr);
	X509_gmtime_adj(X509_getm_notBefore(certificate.get()), 0);
	X509_gmtime_adj(X509_getm_notAfter(certificate.get()), 86400);
	set_name(X509_get_subject_name(certificate.get()), "Test CA");
	require(X509_set_issuer_name(certificate.get(), X509_get_subject_name(certificate.get())) == 1);
	require(X509_set_pubkey(certificate.get(), key) == 1);
	add_extension(certificate.get(), certificate.get(), NID_basic_constraints, "critical,CA:TRUE");
	add_extension(certificate.get(), certificate.get(), NID_key_usage, "critical,keyCertSign,cRLSign");
	require(X509_sign(certificate.get(), key, EVP_sha256()) > 0);
	return certificate;
}

X509ReqPtr make_csr(EVP_PKEY *key)
{
	X509ReqPtr request{X509_REQ_new()};
	require(request != nullptr);
	require(X509_REQ_set_version(request.get(), 0) == 1);
	set_name(X509_REQ_get_subject_name(request.get()), "leaf");
	require(X509_REQ_set_pubkey(request.get(), key) == 1);
	require(X509_REQ_sign(request.get(), key, EVP_sha256()) > 0);
	return request;
}

void write_file(const std::filesystem::path &path, const std::string &contents)
{
	std::ofstream output{path, std::ios::binary | std::ios::trunc};
	output << contents;
}

std::string read_file(const std::filesystem::path &path)
{
	std::ifstream input{path, std::ios::binary};
	std::ostringstream contents;
	contents << input.rdbuf();
	return contents.str();
}

std::string shell_quote(const std::filesystem::path &path)
{
	const std::string value = path.string();
#if defined(_WIN32)
	require(value.find('"') == std::string::npos);
	return "\"" + value + "\"";
#else
	std::string quoted = "'";
	for (const char ch : value)
	{
		if (ch == '\'')
		{
			quoted += "'\\''";
		}
		else
		{
			quoted.push_back(ch);
		}
	}
	quoted.push_back('\'');
	return quoted;
#endif
}

std::string json_escape(const std::string &value)
{
	std::string escaped;
	for (const char ch : value)
	{
		switch (ch)
		{
		case '\\':
			escaped += "\\\\";
			break;
		case '"':
			escaped += "\\\"";
			break;
		case '\n':
			escaped += "\\n";
			break;
		case '\r':
			escaped += "\\r";
			break;
		case '\t':
			escaped += "\\t";
			break;
		default:
			escaped.push_back(ch);
			break;
		}
	}
	return escaped;
}

std::string json_string(const std::string &value)
{
	return "\"" + json_escape(value) + "\"";
}

std::string extension_text(X509_EXTENSION *extension)
{
	BioPtr bio{BIO_new(BIO_s_mem())};
	require(bio != nullptr);
	require(X509V3_EXT_print(bio.get(), extension, 0, 0) == 1);
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

X509_EXTENSION *extension_by_nid(X509 *certificate, int nid)
{
	const int index = X509_get_ext_by_NID(certificate, nid, -1);
	require(index >= 0);
	X509_EXTENSION *extension = X509_get_ext(certificate, index);
	require(extension != nullptr);
	return extension;
}

void assert_profile_extensions(X509 *certificate)
{
	X509_EXTENSION *basic_extension = extension_by_nid(certificate, NID_basic_constraints);
	require(X509_EXTENSION_get_critical(basic_extension) == 1);
	BasicConstraintsPtr basic_constraints{
	    static_cast<BASIC_CONSTRAINTS *>(X509V3_EXT_d2i(basic_extension))};
	require(basic_constraints != nullptr);
	require(basic_constraints->ca == 0);

	X509_EXTENSION *key_usage_extension = extension_by_nid(certificate, NID_key_usage);
	require(X509_EXTENSION_get_critical(key_usage_extension) == 1);
	Asn1BitStringPtr key_usage{static_cast<ASN1_BIT_STRING *>(X509V3_EXT_d2i(key_usage_extension))};
	require(key_usage != nullptr);
	require(ASN1_BIT_STRING_get_bit(key_usage.get(), 0) == 1);
	require(ASN1_BIT_STRING_get_bit(key_usage.get(), 2) == 1);

	X509_EXTENSION *eku_extension = extension_by_nid(certificate, NID_ext_key_usage);
	ExtendedKeyUsagePtr eku{static_cast<EXTENDED_KEY_USAGE *>(X509V3_EXT_d2i(eku_extension))};
	require(eku != nullptr);
	require(sk_ASN1_OBJECT_num(eku.get()) == 1);
	require(OBJ_obj2nid(sk_ASN1_OBJECT_value(eku.get(), 0)) == NID_server_auth);

	(void)extension_by_nid(certificate, NID_subject_key_identifier);
	(void)extension_by_nid(certificate, NID_authority_key_identifier);
	(void)extension_by_nid(certificate, NID_subject_alt_name);

	const std::string aia = extension_text(extension_by_nid(certificate, NID_info_access));
	require(aia.find("URI:https://pki.example.test/issuers/test-ca.pem") != std::string::npos);
	const std::string crl = extension_text(extension_by_nid(certificate, NID_crl_distribution_points));
	require(crl.find("URI:https://pki.example.test/crl/test-ca.crl") != std::string::npos);
}

std::string issue_request_json(const std::string &csr_pem, const std::string &issuer_certificate_pem, const std::filesystem::path &issuer_key_path, const std::string &extra_fields)
{
	return "{"
	       "\"csr_pem\":" +
	       json_string(csr_pem) +
	       ",\"issuer_certificate_pem\":" + json_string(issuer_certificate_pem) +
	       ",\"issuer_key_ref\":" + json_string(issuer_key_path.string()) +
	       ",\"subject\":\"CN=leaf\""
	       ",\"aia_url\":\"https://pki.example.test/issuers/test-ca.pem\""
	       ",\"crl_distribution_points\":[\"https://pki.example.test/crl/test-ca.crl\"]"
	       ",\"dns_names\":[\"leaf.example.test\"]"
	       ",\"not_before\":\"2026-06-13T00:00:00Z\""
	       ",\"not_after\":\"2026-06-14T00:00:00Z\"" +
	       extra_fields +
	       "}";
}

void assert_cli_failure_contains(const std::filesystem::path &cli_path, const std::filesystem::path &request_path, const std::filesystem::path &out_path, const std::filesystem::path &stderr_path, const std::string &expected_code)
{
#if defined(_WIN32)
	const std::string command_prefix = "call ";
	const std::string stdout_target = "nul";
#else
	const std::string command_prefix;
	const std::string stdout_target = "/dev/null";
#endif
	const std::string command = command_prefix + shell_quote(cli_path) +
	                            " cert issue --request " + shell_quote(request_path) +
	                            " --out " + shell_quote(out_path) +
	                            " > " + stdout_target + " 2> " + shell_quote(stderr_path);
	const int exit_code = std::system(command.c_str());
	const std::string stderr_output = read_file(stderr_path);
	if (exit_code == 0 || stderr_output.find(expected_code) == std::string::npos)
	{
		std::cerr << "CLI issue parser contract mismatch\n"
		          << "command: " << command << "\n"
		          << "exit_code: " << exit_code << "\n"
		          << "expected_code: " << expected_code << "\n"
		          << "stderr: " << stderr_output << "\n";
		std::exit(1);
	}
}

void assert_cli_parses_profile_extension_fields(const std::filesystem::path &cli_path, const std::filesystem::path &work_dir, const std::string &csr_pem, const std::string &issuer_certificate_pem, const std::filesystem::path &issuer_key_path)
{
	const std::filesystem::path out_path = work_dir / "core_issue_profile_cli_out.json";
	const std::filesystem::path stderr_path = work_dir / "core_issue_profile_cli_stderr.json";

	const std::filesystem::path pathlen_request_path = work_dir / "core_issue_profile_cli_pathlen_request.json";
	write_file(
	    pathlen_request_path,
	    issue_request_json(
	        csr_pem,
	        issuer_certificate_pem,
	        issuer_key_path,
	        ",\"basic_constraints_ca\":false,\"basic_constraints_max_path_len\":0"));
	assert_cli_failure_contains(cli_path, pathlen_request_path, out_path, stderr_path, "issue.certificate_create_failed");

	const std::filesystem::path key_usage_request_path = work_dir / "core_issue_profile_cli_key_usage_request.json";
	write_file(
	    key_usage_request_path,
	    issue_request_json(
	        csr_pem,
	        issuer_certificate_pem,
	        issuer_key_path,
	        ",\"basic_constraints_ca\":true,\"key_usage\":[\"not_a_key_usage\"]"));
	assert_cli_failure_contains(cli_path, key_usage_request_path, out_path, stderr_path, "issue.certificate_create_failed");
}

} // namespace

int main(int argc, char *argv[])
{
	require(argc == 3);
	const std::filesystem::path cli_path = argv[1];
	const std::filesystem::path work_dir = argv[2];
	const EvpPkeyPtr ca_key = make_rsa_key();
	const X509Ptr ca_certificate = make_ca_certificate(ca_key.get());
	const EvpPkeyPtr leaf_key = make_rsa_key();
	const X509ReqPtr csr = make_csr(leaf_key.get());

	const std::filesystem::path issuer_key_path = work_dir / "core_issue_profile_issuer.key";
	write_file(issuer_key_path, private_key_to_pem(ca_key.get()));

	modern_pki::core::IssueRequest request;
	request.csr_pem = csr_to_pem(csr.get());
	request.issuer_certificate_pem = certificate_to_pem(ca_certificate.get());
	request.issuer_key_ref = issuer_key_path.string();
	request.subject = "CN=leaf";
	request.dns_names = {"leaf.example.test"};
	request.not_before = "2026-06-13T00:00:00Z";
	request.not_after = "2026-06-14T00:00:00Z";
	request.basic_constraints_critical = true;
	request.basic_constraints_ca = false;
	request.key_usage_critical = true;
	request.key_usage = {"digital_signature", "key_encipherment"};
	request.extended_key_usage = {"server_auth"};
	request.subject_key_identifier = true;
	request.authority_key_identifier = true;
	request.aia_url = "https://pki.example.test/issuers/test-ca.pem";
	request.crl_distribution_points = {"https://pki.example.test/crl/test-ca.crl"};

	const modern_pki::core::IssueResult result = modern_pki::core::issue_certificate(request);
	const X509Ptr certificate = certificate_from_pem(result.certificate_pem);
	assert_profile_extensions(certificate.get());
	assert_cli_parses_profile_extension_fields(
	    cli_path, work_dir, request.csr_pem, request.issuer_certificate_pem, issuer_key_path);
	return 0;
}
