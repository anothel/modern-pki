#include "modern_pki/core/csr.hpp"
#include "modern_pki/core/issue.hpp"

#include <cassert>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace
{

std::string read_file(const std::filesystem::path &path)
{
	std::ifstream input{path, std::ios::binary};
	if (!input.good())
	{
		std::cerr << "failed to open file: " << path << "\n";
		std::exit(1);
	}
	std::ostringstream contents;
	contents << input.rdbuf();
	return contents.str();
}

void write_file(const std::filesystem::path &path, const std::string &contents)
{
	std::ofstream output{path, std::ios::binary | std::ios::trunc};
	output << contents;
}

std::string shell_quote(const std::filesystem::path &path)
{
	const std::string value = path.string();
#if defined(_WIN32)
	assert(value.find('"') == std::string::npos);
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

void assert_cli_failure_contains(
    const std::filesystem::path &cli_path,
    const std::filesystem::path &stdout_path,
    const std::filesystem::path &stderr_path,
    const std::string &args,
    const std::string &expected_code)
{
#if defined(_WIN32)
	const std::string command_prefix = "call ";
#else
	const std::string command_prefix;
#endif
	const std::string command = command_prefix + shell_quote(cli_path) + " " + args + " > " + shell_quote(stdout_path) + " 2> " + shell_quote(stderr_path);
	const int exit_code = std::system(command.c_str());
	const std::string stderr_output = read_file(stderr_path);

	if (exit_code == 0 || stderr_output.find(expected_code) == std::string::npos)
	{
		std::cerr << "CLI failure contract mismatch\n"
		          << "command: " << command << "\n"
		          << "exit_code: " << exit_code << "\n"
		          << "expected_code: " << expected_code << "\n"
		          << "stderr: " << stderr_output << "\n";
		std::exit(1);
	}
}

void assert_cli_success_contains(
    const std::filesystem::path &cli_path,
    const std::filesystem::path &stdout_path,
    const std::filesystem::path &stderr_path,
    const std::string &args,
    const std::filesystem::path &output_path,
    const std::vector<std::string> &expected_fragments)
{
#if defined(_WIN32)
	const std::string command_prefix = "call ";
#else
	const std::string command_prefix;
#endif
	const std::string command = command_prefix + shell_quote(cli_path) + " " + args + " > " + shell_quote(stdout_path) + " 2> " + shell_quote(stderr_path);
	std::filesystem::remove(output_path);
	const int exit_code = std::system(command.c_str());
	const std::string stderr_output = read_file(stderr_path);
	const std::string output = read_file(output_path);

	for (const std::string &fragment : expected_fragments)
	{
		if (exit_code != 0 || output.find(fragment) == std::string::npos)
		{
			std::cerr << "CLI success contract mismatch\n"
			          << "command: " << command << "\n"
			          << "exit_code: " << exit_code << "\n"
			          << "expected_fragment: " << fragment << "\n"
			          << "stderr: " << stderr_output << "\n"
			          << "output: " << output << "\n";
			std::exit(1);
		}
	}
}

std::optional<unsigned char> base64_value(char value)
{
	if (value >= 'A' && value <= 'Z')
	{
		return static_cast<unsigned char>(value - 'A');
	}
	if (value >= 'a' && value <= 'z')
	{
		return static_cast<unsigned char>(value - 'a' + 26);
	}
	if (value >= '0' && value <= '9')
	{
		return static_cast<unsigned char>(value - '0' + 52);
	}
	if (value == '+')
	{
		return 62;
	}
	if (value == '/')
	{
		return 63;
	}
	return std::nullopt;
}

std::string decode_base64(std::string_view input)
{
	std::string output;
	unsigned int accumulator = 0;
	int bits = -8;
	for (char ch : input)
	{
		if (ch == '=')
		{
			break;
		}
		const std::optional<unsigned char> value = base64_value(ch);
		if (!value.has_value())
		{
			continue;
		}
		accumulator = ((accumulator << 6) | *value) & 0xffffff;
		bits += 6;
		if (bits >= 0)
		{
			output.push_back(static_cast<char>((accumulator >> bits) & 0xff));
			bits -= 8;
		}
	}
	return output;
}

void assert_cli_error_contract(const std::filesystem::path &cli_path, const std::filesystem::path &work_dir)
{
	const std::filesystem::path stdout_path = work_dir / "core_cli_contract_stdout.txt";
	const std::filesystem::path stderr_path = work_dir / "core_cli_contract_stderr.txt";
	const std::filesystem::path malformed_request_path = work_dir / "core_cli_contract_malformed_request.json";
	const std::filesystem::path result_path = work_dir / "core_cli_contract_result.json";

	assert_cli_failure_contains(cli_path, stdout_path, stderr_path, "invalid", "\"code\":\"cli.invalid_args\"");

	write_file(malformed_request_path, "{");
	assert_cli_failure_contains(
	    cli_path,
	    stdout_path,
	    stderr_path,
	    "cert issue --request " + shell_quote(malformed_request_path) + " --out " + shell_quote(result_path),
	    "\"code\":\"cli.json_parse_failed\"");
}

void assert_cli_ocsp_fixture_inspect(
    const std::filesystem::path &cli_path,
    const std::filesystem::path &work_dir,
    const std::filesystem::path &fixture_dir)
{
	const std::filesystem::path stdout_path = work_dir / "core_cli_contract_ocsp_stdout.txt";
	const std::filesystem::path stderr_path = work_dir / "core_cli_contract_ocsp_stderr.txt";
	const std::filesystem::path request_path = work_dir / "core_cli_contract_ocsp_request.der";
	const std::filesystem::path result_path = work_dir / "core_cli_contract_ocsp_result.json";

	write_file(request_path, decode_base64(read_file(fixture_dir / "curated-single-request.der.b64")));
	assert_cli_success_contains(
	    cli_path,
	    stdout_path,
	    stderr_path,
	    "ocsp inspect --in " + shell_quote(request_path) + " --out " + shell_quote(result_path),
	    result_path,
	    {
	        "\"serial_number\":\"1001\"",
	        "\"issuer_name_hash\":\"84378ae02c8a13718b0efda0e3a283b0006a4265\"",
	        "\"issuer_key_hash\":\"d5dcea91c8d109ec61e84d07bea04fab0b720ac3\"",
	    });
}

} // namespace

int main(int argc, char *argv[])
{
	assert(argc == 4);
	assert_cli_error_contract(argv[1], argv[2]);
	assert_cli_ocsp_fixture_inspect(argv[1], argv[2], argv[3]);

	modern_pki::core::IssueRequest request;
	request.csr_pem = "csr";
	request.issuer_certificate_pem = "issuer";
	request.issuer_key_ref = "issuer.key";
	request.subject = "CN=leaf";
	request.dns_names = {"leaf.example.test"};
	request.ip_addresses = {"127.0.0.1"};
	request.not_before = "2026-06-13T00:00:00Z";
	request.not_after = "2026-09-11T00:00:00Z";
	request.signature_algorithm = "rsa_with_sha256";
	request.profile_id = "profile-1";
	request.basic_constraints_critical = true;
	request.basic_constraints_ca = false;
	request.key_usage_critical = true;
	request.key_usage = {"digital_signature", "key_encipherment"};
	request.extended_key_usage = {"server_auth"};
	request.subject_key_identifier = true;
	request.authority_key_identifier = true;

	assert(request.csr_pem == "csr");
	assert(request.issuer_certificate_pem == "issuer");
	assert(request.issuer_key_ref == "issuer.key");
	assert(request.subject == "CN=leaf");
	assert(request.dns_names == std::vector<std::string>{"leaf.example.test"});
	assert(request.ip_addresses == std::vector<std::string>{"127.0.0.1"});
	assert(request.not_before == "2026-06-13T00:00:00Z");
	assert(request.not_after == "2026-09-11T00:00:00Z");
	assert(request.signature_algorithm == "rsa_with_sha256");
	assert(request.profile_id == "profile-1");
	assert(request.basic_constraints_critical);
	assert(!request.basic_constraints_ca);
	assert(request.key_usage_critical);
	const std::vector<std::string> expected_key_usage{"digital_signature", "key_encipherment"};
	const std::vector<std::string> expected_extended_key_usage{"server_auth"};
	assert(request.key_usage == expected_key_usage);
	assert(request.extended_key_usage == expected_extended_key_usage);
	assert(request.subject_key_identifier);
	assert(request.authority_key_identifier);

	modern_pki::core::IssueResult result;
	result.certificate_pem = "cert";
	result.serial_number = "123";
	result.subject = request.subject;
	result.not_before = request.not_before;
	result.not_after = request.not_after;

	assert(result.certificate_pem == "cert");
	assert(result.serial_number == "123");
	assert(result.subject == "CN=leaf");
	assert(result.not_before == "2026-06-13T00:00:00Z");
	assert(result.not_after == "2026-09-11T00:00:00Z");

	modern_pki::core::CsrInfo csr_info;
	csr_info.subject = "CN=leaf";
	csr_info.dns_names = {"leaf.example.test"};
	csr_info.ip_addresses = {"127.0.0.1"};

	assert(csr_info.subject == "CN=leaf");
	assert(csr_info.dns_names == std::vector<std::string>{"leaf.example.test"});
	assert(csr_info.ip_addresses == std::vector<std::string>{"127.0.0.1"});

	return 0;
}
