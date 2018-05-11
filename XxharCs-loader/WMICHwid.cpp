#include "XorStr.h"
#include "WMICHwid.h"

bool WMICHwid::query()
{
	auto strip_keyword = [](std::string& buffer, const bool filter_digits = false)
	{
		std::string current, stripped;
		std::istringstream iss(buffer);

		buffer.clear();
		auto first_tick = false;
		while (std::getline(iss, current)) {
			if (!first_tick) {
				first_tick = true;
				continue;
			}
			if (filter_digits && std::isdigit(current.at(0))) {
				continue;
			}

			buffer.append(current).append("\n");
		}
		if (buffer.back() == '\n') {
			buffer.pop_back();
		}
	};

	if (!query_wmic(_xor_("wmic cpu get name"), m_CPU) ||
		!query_wmic(_xor_("WMIC OS GET CSName"), m_ComputerName) ||
		!query_wmic(_xor_("WMIC diskdrive get SerialNumber"), m_Physical)) {
		return false;
	}

	strip_keyword(m_CPU);
	strip_keyword(m_ComputerName);
	strip_keyword(m_Physical, true);

	return true;
}

bool WMICHwid::query_wmic(const std::string& input, std::string& out)
{
	auto* shell_cmd = _popen(input.c_str(), "r");
	if (!shell_cmd) {
		return false;
	}

	static char buffer[1024] = {};
	while (fgets(buffer, 1024, shell_cmd)) {
		out.append(buffer);
	}

	_pclose(shell_cmd);
	while (out.back() == '\n' ||
		out.back() == '\0' ||
		out.back() == ' ' ||
		out.back() == '\r' ||
		out.back() == '\t') {
		out.pop_back();
	}

	return !out.empty();
}