/* C-Compat Headers */
#include <cstdint>
#include <cstdlib>
#include <cerrno>
#include <cstring>

/* C-Noncompat Headers */
#include <unistd.h>
#include <netdb.h>

/* Subheaders */
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

/* C++ Headers */
#include <string>
#include <vector>
#include <exception>
#include <memory>
#include <iostream>
#include <sstream>
#include <iomanip>


class socket {
        public:

                socket(uint32_t port, std::string addr);
                ~socket(void);

                void send(std::vector<uint8_t> data);
                void send(std::string data);
                std::vector<uint8_t> recv_vec(void);
                std::string recv_str(void);

        private:
                const uint32_t port;
                const std::string addr;
                int32_t sockfd;
                addrinfo hints;
                addrinfo * servinfo;

                bool valid_port(uint32_t port);
};