#include "modern_pki/core/csr.hpp"

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <iomanip>
#include <limits>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>

namespace modern_pki::core
{
namespace
{

struct BioDeleter
{
	void operator()(BIO *bio) const noexcept
	{
		BIO_free(bio);
	}
};

struct X509ReqDeleter
{
	void operator()(X509_REQ *request) const noexcept
	{
		X509_REQ_free(request);
	}
};

struct X509ExtensionStackDeleter
{
	void operator()(STACK_OF(X509_EXTENSION) * extensions) const noexcept
	{
		sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);
	}
};

struct GeneralNamesDeleter
{
	void operator()(GENERAL_NAMES *names) const noexcept
	{
		GENERAL_NAMES_free(names);
	}
};

struct OpenSslFreeDeleter
{
	void operator()(char *value) const noexcept
	{
		OPENSSL_free(value);
	}
};

using BioPtr = std::unique_ptr<BIO, BioDeleter>;
using X509ReqPtr = std::unique_ptr<X509_REQ, X509ReqDeleter>;
using X509ExtensionStackPtr = std::unique_ptr<STACK_OF(X509_EXTENSION), X509ExtensionStackDeleter>;
using GeneralNamesPtr = std::unique_ptr<GENERAL_NAMES, GeneralNamesDeleter>;
using OpenSslStringPtr = std::unique_ptr<char, OpenSslFreeDeleter>;

std::string asn1_string_to_text(const ASN1_STRING *value)
{
	if (value == nullptr)
	{
		throw std::runtime_error{"csr.parse_failed"};
	}

	const unsigned char *data = ASN1_STRING_get0_data(value);
	const int length = ASN1_STRING_length(value);
	if (data == nullptr || length < 0)
	{
		throw std::runtime_error{"csr.parse_failed"};
	}

	return std::string{reinterpret_cast<const char *>(data), static_cast<std::string::size_type>(length)};
}

std::string format_ipv4(const unsigned char *data)
{
	std::ostringstream stream;
	stream << static_cast<int>(data[0]) << '.' << static_cast<int>(data[1]) << '.' << static_cast<int>(data[2]) << '.'
	       << static_cast<int>(data[3]);
	return stream.str();
}

std::string format_ipv6(const unsigned char *data)
{
	std::ostringstream stream;
	stream << std::hex << std::setfill('0');
	for (int index = 0; index < 16; index += 2)
	{
		if (index != 0)
		{
			stream << ':';
		}
		const unsigned int group = static_cast<unsigned int>(data[index]) << 8U | static_cast<unsigned int>(data[index + 1]);
		stream << std::setw(4) << group;
	}
	return stream.str();
}

std::string ip_address_to_text(const ASN1_OCTET_STRING *value)
{
	if (value == nullptr)
	{
		throw std::runtime_error{"csr.parse_failed"};
	}

	const unsigned char *data = ASN1_STRING_get0_data(value);
	const int length = ASN1_STRING_length(value);
	if (data == nullptr)
	{
		throw std::runtime_error{"csr.parse_failed"};
	}
	if (length == 4)
	{
		return format_ipv4(data);
	}
	if (length == 16)
	{
		return format_ipv6(data);
	}
	throw std::runtime_error{"csr.parse_failed"};
}

void append_subject_alt_names_from_extension(const X509_EXTENSION *extension, CsrInfo &info)
{
	GeneralNamesPtr names{static_cast<GENERAL_NAMES *>(X509V3_EXT_d2i(const_cast<X509_EXTENSION *>(extension)))};
	if (!names)
	{
		throw std::runtime_error{"csr.parse_failed"};
	}

	const int count = sk_GENERAL_NAME_num(names.get());
	for (int index = 0; index < count; ++index)
	{
		const GENERAL_NAME *name = sk_GENERAL_NAME_value(names.get(), index);
		if (name == nullptr)
		{
			throw std::runtime_error{"csr.parse_failed"};
		}
		switch (name->type)
		{
		case GEN_DNS:
			info.dns_names.push_back(asn1_string_to_text(name->d.dNSName));
			break;
		case GEN_IPADD:
			info.ip_addresses.push_back(ip_address_to_text(name->d.iPAddress));
			break;
		default:
			break;
		}
	}
}

void append_subject_alt_names(X509_REQ *request, CsrInfo &info)
{
	X509ExtensionStackPtr extensions{X509_REQ_get_extensions(request)};
	if (!extensions)
	{
		return;
	}

	const int count = sk_X509_EXTENSION_num(extensions.get());
	for (int index = 0; index < count; ++index)
	{
		const X509_EXTENSION *extension = sk_X509_EXTENSION_value(extensions.get(), index);
		if (extension == nullptr)
		{
			throw std::runtime_error{"csr.parse_failed"};
		}
		const ASN1_OBJECT *object = X509_EXTENSION_get_object(const_cast<X509_EXTENSION *>(extension));
		if (object != nullptr && OBJ_obj2nid(object) == NID_subject_alt_name)
		{
			append_subject_alt_names_from_extension(extension, info);
		}
	}
}

} // namespace

CsrInfo inspect_csr_pem(const std::string &csr_pem)
{
	if (csr_pem.size() > static_cast<std::string::size_type>(std::numeric_limits<int>::max()))
	{
		throw std::runtime_error{"csr.input_too_large"};
	}

	BioPtr bio{BIO_new_mem_buf(csr_pem.data(), static_cast<int>(csr_pem.size()))};
	if (!bio)
	{
		throw std::runtime_error{"csr.bio_create_failed"};
	}

	X509ReqPtr request{PEM_read_bio_X509_REQ(bio.get(), nullptr, nullptr, nullptr)};
	if (!request)
	{
		throw std::runtime_error{"csr.parse_failed"};
	}

	X509_NAME *subject_name = X509_REQ_get_subject_name(request.get());
	if (!subject_name)
	{
		throw std::runtime_error{"csr.parse_failed"};
	}

	OpenSslStringPtr subject{X509_NAME_oneline(subject_name, nullptr, 0)};
	if (!subject)
	{
		throw std::runtime_error{"csr.parse_failed"};
	}

	CsrInfo info;
	info.subject = subject.get();
	append_subject_alt_names(request.get(), info);
	return info;
}

} // namespace modern_pki::core
