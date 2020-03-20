#pragma once

#include <string>

#ifndef REGISTER_HPP
#define REGISTER_HPP
class Register {
	public:
		Register(std::string name, int64_t value, bool pc);
		std::string name;
		int64_t value;
		bool pc;
};
#endif