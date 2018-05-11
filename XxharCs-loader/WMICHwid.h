#pragma once

#include <cctype>
#include <sstream>
#include <string>

class WMICHwid
{

public:

	WMICHwid() = default;

	bool query();
	inline const std::string &getCPU() const;
	inline const std::string &getComputerName() const;
	inline const std::string &getPhysicalHddSerial() const;

private:

	static bool query_wmic(const std::string &input, std::string &out);

protected:

	std::string m_CPU;
	std::string m_ComputerName;
	std::string m_Physical;
};

inline const std::string& WMICHwid::getCPU() const
{
	return m_CPU;
}

inline const std::string& WMICHwid::getComputerName() const
{
	return m_ComputerName;
}

inline const std::string& WMICHwid::getPhysicalHddSerial() const
{
	return m_Physical;
}