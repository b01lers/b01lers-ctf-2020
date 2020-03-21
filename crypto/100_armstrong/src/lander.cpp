#include "sockets.hpp"
#include <fstream>
#include <vector>

#ifndef HOST
#define HOST "127.0.0.1"
#endif

#ifndef PORT
#define PORT 4001
#endif

int main() {
	::remove("./chal.png");
	std::ofstream img_file;
	std::cout << "Captain: We're landing on the moon now. Ladies and gentlemen, please hold tight!" << std::endl;

	std::cout << "Captain: Ladies and gentlemen, we have landed! Coming through to the screens in front of you is the first picture of the moon!" << std::endl;

	img_file.open("chal.png", std::ios::out | std::ios::app | std::ios::binary);
	class socket s(PORT, HOST);
	for (uint8_t bt : s.recv_vec()) {
		img_file << bt;
	}
	img_file.close();

	std::cout << "Captain: Oh no...looks like our camera is corrupted. Well, hop out if you wanna see in person!" << std::endl;
	exit(0);
}