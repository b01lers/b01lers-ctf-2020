#include "register.hpp"

Register::Register(std::string name, int64_t value, bool pc) {
	this->name = name;
	this->value = value;
	this->pc = pc;
}