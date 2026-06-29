#include "modern_pki/core/crl.hpp"
#include "modern_pki/core/csr.hpp"
#include "modern_pki/core/ocsp.hpp"

#include <openssl/err.h>

#include <cstddef>
#include <cstdint>
#include <exception>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size)
{
	const std::string input{reinterpret_cast<const char *>(data), size};
	ERR_clear_error();
	try
	{
#if defined(MODERN_PKI_FUZZ_CSR)
		(void)modern_pki::core::inspect_csr_pem(input);
#elif defined(MODERN_PKI_FUZZ_OCSP)
		(void)modern_pki::core::inspect_ocsp_request_der(input);
#elif defined(MODERN_PKI_FUZZ_CRL)
		(void)modern_pki::core::inspect_crl_der(input);
#else
#error "No parser fuzzer selected"
#endif
	}
	catch (const std::exception &)
	{
	}
	catch (...)
	{
	}
	ERR_clear_error();
	return 0;
}
