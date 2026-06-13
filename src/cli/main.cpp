#include "modern_pki/core/csr.hpp"
#include "modern_pki/core/issue.hpp"

#include <cctype>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace
{

struct JsonValue
{
	bool is_array = false;
	bool is_null = false;
	bool is_bool = false;
	bool is_number = false;
	std::string string_value;
	std::vector<std::string> array_value;
	bool bool_value = false;
	int number_value = 0;
};

using JsonObject = std::map<std::string, JsonValue>;

[[noreturn]] void throw_json_parse_failed()
{
	throw std::runtime_error{"cli.json_parse_failed"};
}

class JsonParser
{
public:
	explicit JsonParser(std::string_view input)
	    : input_{input}
	{
	}

	JsonObject parse_object()
	{
		JsonObject object;
		expect('{');
		skip_ws();
		if (consume('}'))
		{
			skip_ws();
			if (position_ != input_.size())
			{
				throw_json_parse_failed();
			}
			return object;
		}

		while (true)
		{
			std::string key = parse_string();
			expect(':');
			object[key] = parse_value();
			skip_ws();
			if (consume('}'))
			{
				break;
			}
			expect(',');
		}

		skip_ws();
		if (position_ != input_.size())
		{
			throw_json_parse_failed();
		}
		return object;
	}

private:
	void skip_ws()
	{
		while (position_ < input_.size())
		{
			const char ch = input_[position_];
			if (ch != ' ' && ch != '\n' && ch != '\r' && ch != '\t')
			{
				return;
			}
			++position_;
		}
	}

	bool consume(char expected)
	{
		skip_ws();
		if (position_ < input_.size() && input_[position_] == expected)
		{
			++position_;
			return true;
		}
		return false;
	}

	void expect(char expected)
	{
		if (!consume(expected))
		{
			throw_json_parse_failed();
		}
	}

	JsonValue parse_value()
	{
		skip_ws();
		if (position_ >= input_.size())
		{
			throw_json_parse_failed();
		}

		if (input_[position_] == '"')
		{
			JsonValue value;
			value.string_value = parse_string();
			return value;
		}

		if (input_[position_] == '[')
		{
			JsonValue value;
			value.is_array = true;
			value.array_value = parse_string_array();
			return value;
		}

		if (consume_literal("null"))
		{
			JsonValue value;
			value.is_null = true;
			return value;
		}
		if (consume_literal("true"))
		{
			JsonValue value;
			value.is_bool = true;
			value.bool_value = true;
			return value;
		}
		if (consume_literal("false"))
		{
			JsonValue value;
			value.is_bool = true;
			return value;
		}
		if (input_[position_] == '-' || std::isdigit(static_cast<unsigned char>(input_[position_])))
		{
			JsonValue value;
			value.is_number = true;
			value.number_value = parse_integer();
			return value;
		}

		throw_json_parse_failed();
	}

	bool consume_literal(std::string_view literal)
	{
		if (input_.substr(position_, literal.size()) != literal)
		{
			return false;
		}
		position_ += literal.size();
		return true;
	}

	std::vector<std::string> parse_string_array()
	{
		std::vector<std::string> values;
		expect('[');
		skip_ws();
		if (consume(']'))
		{
			return values;
		}

		while (true)
		{
			values.push_back(parse_string());
			skip_ws();
			if (consume(']'))
			{
				break;
			}
			expect(',');
		}
		return values;
	}

	int parse_integer()
	{
		bool negative = false;
		if (input_[position_] == '-')
		{
			negative = true;
			++position_;
		}
		if (position_ >= input_.size() || !std::isdigit(static_cast<unsigned char>(input_[position_])))
		{
			throw_json_parse_failed();
		}
		int value = 0;
		while (position_ < input_.size() && std::isdigit(static_cast<unsigned char>(input_[position_])))
		{
			value = (value * 10) + (input_[position_] - '0');
			++position_;
		}
		return negative ? -value : value;
	}

	std::string parse_string()
	{
		skip_ws();
		if (position_ >= input_.size() || input_[position_] != '"')
		{
			throw_json_parse_failed();
		}
		++position_;

		std::string value;
		while (position_ < input_.size())
		{
			const char ch = input_[position_++];
			if (ch == '"')
			{
				return value;
			}
			if (ch != '\\')
			{
				value.push_back(ch);
				continue;
			}
			if (position_ >= input_.size())
			{
				throw_json_parse_failed();
			}
			const char escaped = input_[position_++];
			switch (escaped)
			{
			case '\\':
				value.push_back('\\');
				break;
			case '"':
				value.push_back('"');
				break;
			case 'n':
				value.push_back('\n');
				break;
			case 'r':
				value.push_back('\r');
				break;
			case 't':
				value.push_back('\t');
				break;
			default:
				throw_json_parse_failed();
			}
		}

		throw_json_parse_failed();
	}

	std::string_view input_;
	std::string_view::size_type position_ = 0;
};

std::string read_file(const std::string &path)
{
	std::ifstream input{path, std::ios::binary};
	if (!input)
	{
		throw std::runtime_error{"cli.read_failed"};
	}

	std::ostringstream contents;
	contents << input.rdbuf();
	if (input.bad())
	{
		throw std::runtime_error{"cli.read_failed"};
	}
	return contents.str();
}

void write_file(const std::string &path, std::string_view contents)
{
	std::ofstream output{path, std::ios::binary | std::ios::trunc};
	if (!output)
	{
		throw std::runtime_error{"cli.write_failed"};
	}

	output << contents;
	if (!output)
	{
		throw std::runtime_error{"cli.write_failed"};
	}
}

std::string json_escape(std::string_view value)
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

std::string json_string(std::string_view value)
{
	return "\"" + json_escape(value) + "\"";
}

std::string json_string_array(const std::vector<std::string> &values)
{
	std::string output = "[";
	for (std::vector<std::string>::size_type index = 0; index < values.size(); ++index)
	{
		if (index != 0)
		{
			output.push_back(',');
		}
		output += json_string(values[index]);
	}
	output.push_back(']');
	return output;
}

std::string json_error(std::string_view code, std::string_view message)
{
	return "{\"code\":" + json_string(code) + ",\"message\":" + json_string(message) + "}";
}

void write_error(std::string_view code, std::string_view message)
{
	std::cerr << json_error(code, message) << '\n';
}

std::string get_string_field(const JsonObject &object, const std::string &key)
{
	const auto found = object.find(key);
	if (found == object.end())
	{
		return {};
	}
	if (found->second.is_array || found->second.is_null || found->second.is_bool || found->second.is_number)
	{
		throw_json_parse_failed();
	}
	return found->second.string_value;
}

std::vector<std::string> get_string_array_field(const JsonObject &object, const std::string &key)
{
	const auto found = object.find(key);
	if (found == object.end())
	{
		return {};
	}
	if (found->second.is_null)
	{
		return {};
	}
	if (!found->second.is_array)
	{
		throw_json_parse_failed();
	}
	return found->second.array_value;
}

bool get_bool_field(const JsonObject &object, const std::string &key)
{
	const auto found = object.find(key);
	if (found == object.end() || found->second.is_null)
	{
		return false;
	}
	if (!found->second.is_bool)
	{
		throw_json_parse_failed();
	}
	return found->second.bool_value;
}

int get_int_field(const JsonObject &object, const std::string &key, int default_value)
{
	const auto found = object.find(key);
	if (found == object.end() || found->second.is_null)
	{
		return default_value;
	}
	if (!found->second.is_number)
	{
		throw_json_parse_failed();
	}
	return found->second.number_value;
}

modern_pki::core::IssueRequest issue_request_from_json(std::string_view json)
{
	const JsonObject object = JsonParser{json}.parse_object();

	modern_pki::core::IssueRequest request;
	request.csr_pem = get_string_field(object, "csr_pem");
	request.issuer_certificate_pem = get_string_field(object, "issuer_certificate_pem");
	request.issuer_key_ref = get_string_field(object, "issuer_key_ref");
	request.subject = get_string_field(object, "subject");
	request.dns_names = get_string_array_field(object, "dns_names");
	request.ip_addresses = get_string_array_field(object, "ip_addresses");
	request.not_before = get_string_field(object, "not_before");
	request.not_after = get_string_field(object, "not_after");
	request.signature_algorithm = get_string_field(object, "signature_algorithm");
	request.profile_id = get_string_field(object, "profile_id");
	request.basic_constraints_critical = get_bool_field(object, "basic_constraints_critical");
	request.basic_constraints_ca = get_bool_field(object, "basic_constraints_ca");
	request.basic_constraints_max_path_len = get_int_field(object, "basic_constraints_max_path_len", -1);
	request.key_usage_critical = get_bool_field(object, "key_usage_critical");
	request.key_usage = get_string_array_field(object, "key_usage");
	request.extended_key_usage_critical = get_bool_field(object, "extended_key_usage_critical");
	request.extended_key_usage = get_string_array_field(object, "extended_key_usage");
	request.subject_key_identifier = get_bool_field(object, "subject_key_identifier");
	request.authority_key_identifier = get_bool_field(object, "authority_key_identifier");
	return request;
}

std::string csr_info_to_json(const modern_pki::core::CsrInfo &info)
{
	return "{\"subject\":" + json_string(info.subject) + ",\"dns_names\":" + json_string_array(info.dns_names) + ",\"ip_addresses\":" + json_string_array(info.ip_addresses) + "}";
}

std::string issue_result_to_json(const modern_pki::core::IssueResult &result)
{
	return "{\"certificate_pem\":" + json_string(result.certificate_pem) + ",\"serial_number\":" + json_string(result.serial_number) + ",\"subject\":" + json_string(result.subject) + ",\"not_before\":" + json_string(result.not_before) + ",\"not_after\":" + json_string(result.not_after) + "}";
}

bool arg_is(char *value, std::string_view expected)
{
	return value != nullptr && expected == value;
}

int run_csr_inspect(int argc, char *argv[])
{
	if (argc != 7 || !arg_is(argv[1], "csr") || !arg_is(argv[2], "inspect") || !arg_is(argv[3], "--in") || !arg_is(argv[5], "--out") || !arg_is(argv[6], "json"))
	{
		write_error("cli.invalid_args", "invalid arguments");
		return 2;
	}

	const std::string csr_pem = read_file(argv[4]);
	const modern_pki::core::CsrInfo info = modern_pki::core::inspect_csr_pem(csr_pem);
	std::cout << csr_info_to_json(info) << '\n';
	return 0;
}

int run_cert_issue(int argc, char *argv[])
{
	if (argc != 7 || !arg_is(argv[1], "cert") || !arg_is(argv[2], "issue") || !arg_is(argv[3], "--request") || !arg_is(argv[5], "--out"))
	{
		write_error("cli.invalid_args", "invalid arguments");
		return 2;
	}

	const modern_pki::core::IssueRequest request = issue_request_from_json(read_file(argv[4]));
	const modern_pki::core::IssueResult result = modern_pki::core::issue_certificate(request);
	write_file(argv[6], issue_result_to_json(result) + "\n");
	return 0;
}

} // namespace

int main(int argc, char *argv[])
{
	try
	{
		if (argc >= 3 && arg_is(argv[1], "csr") && arg_is(argv[2], "inspect"))
		{
			return run_csr_inspect(argc, argv);
		}
		if (argc >= 3 && arg_is(argv[1], "cert") && arg_is(argv[2], "issue"))
		{
			return run_cert_issue(argc, argv);
		}

		write_error("cli.invalid_args", "invalid arguments");
		return 2;
	}
	catch (const std::runtime_error &error)
	{
		write_error(error.what(), error.what());
		return 1;
	}
}
