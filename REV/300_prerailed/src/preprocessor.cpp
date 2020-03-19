#include "preprocessor.hpp"

std::ofstream * out = new std::ofstream("binary", std::ios::out | std::ios::binary);

void usage(std::string executable) {
	std::cout << "Usage: " << executable << " <file>" << std::endl;
	exit(1);
}

int main(int argc, char ** argv) {
	if (argc != 2) {
		usage(std::string(argv[0]));
	}

	/* Validate filename */
	std::string filename(argv[1]);
	std::regex filename_re("^[a-z]+$");
	if (!std::regex_match(filename, filename_re)) {
			std::cout << "Error: filename must be an all-lowercase string" << std::endl;
			usage(std::string(argv[0]));
	}

	yyin = fopen(filename.c_str(), "r+");
	if (yyin == NULL) {
		usage(std::string(argv[0]));
	}
	yyparse();
	out->close();
}
