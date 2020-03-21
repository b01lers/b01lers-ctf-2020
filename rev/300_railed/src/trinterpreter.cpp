#include "trinterpreter.hpp"

Context * ctx = new Context();
uint64_t * linenum = new uint64_t(0);

void usage(std::string executable) {
	std::cout << "Usage: " <<  executable << " <file>" << std::endl;
	exit(1);
}

int main(int argc, char ** argv) {
	if (argc != 2) {
		std::cout << "Error: Must provide exactly one filename" << std::endl;
		usage(std::string(argv[0]));
	}

	/* Validate filename */
	std::string filename(argv[1]);
	std::regex filename_re("^[a-z]+$");
	if (!std::regex_match(filename, filename_re)) {
		std::cout << "Error: filename must be an all-lowercase string" << std::endl;
		exit(1);
	}


	yyin = fopen(filename.c_str(), "r+");
	if (yyin == NULL) {
		usage(std::string(argv[0]));
	}
	yyparse();

	ctx->run();

	delete ctx;

}