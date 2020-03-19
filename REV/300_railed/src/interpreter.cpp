#include <iostream>
#include <fstream>
#include <regex>

void usage(void) {
	std::cout << "Usage: ./trinterpreter <file>" << std::endl;
	exit(1);
}

int main(int argc, char ** argv) {
	if (argc != 2) {
		std::cout << "Error: Must provide exactly one filename" << std::endl;
		usage();
	}

	/* Validate filename */
	std::string filename(argv[1]);
	std::regex filename_re("^[a-z]+$");
	if (!std::regex_match(filename, filename_re)) {
		std::cout << "Error: filename must be an all-lowercase string" << std::endl;
	}




}