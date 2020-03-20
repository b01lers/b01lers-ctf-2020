#ifndef SOCKETS_HPP
#define SOCKETS_HPP
#include "sockets.hpp"
#endif

socket::socket(uint32_t port, std::string addr) 
        : port(port), addr(addr) {

                if (not valid_port(port)) {
                        throw new std::exception();
                }

                memset(&hints, 0, sizeof(hints));
                /* set our hints to any type of connection over stream */
                this->hints.ai_family = AF_UNSPEC;
                this->hints.ai_socktype = SOCK_STREAM;

                if (getaddrinfo(this->addr.c_str(), std::to_string(this->port).c_str(), 
                                        &hints, &servinfo) != 0) {
                        perror("client:getaddrinfo");
                        throw new std::exception();
                }
                addrinfo * p = NULL;
                for (p = this->servinfo; p != NULL; p = p->ai_next) {
                        if ((this->sockfd = ::socket(p->ai_family, p->ai_socktype,
                                                        p->ai_protocol)) == -1) {
                                perror("client:socket");
                                continue;
                        }
                        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
                                perror("client:connect");
                                continue;
                        }
                        break;
                }
                if (p == NULL) {
                        std::cerr << "client: failed to connect" << std::endl;
                }
}

socket::~socket(void) {
        freeaddrinfo(this->servinfo);
        close(this->sockfd);
}

void socket::send(std::vector<uint8_t> data) {
        std::cout << "socket:send" << std::string(data.begin(), data.end()) << std::endl;
        ssize_t sz = ::send(this->sockfd, &data[0], data.size(), 0);
        if (sz == -1) {
                perror("socket:send<vec>");
        }

}

void socket::send(std::string data) {
        std::cout << "socket:send:" << data << std::endl;
        ssize_t sz = ::send(this->sockfd, data.c_str(), data.length(), 0);
        if (sz == -1) {
                perror("socket:send<string>");
        }
}

std::vector<uint8_t> socket::recv_vec(void) {
        ssize_t sz = 0;
        std::vector<uint8_t> recv_buf;
        std::vector<uint8_t> return_buf;
        recv_buf.resize(16);
        do {
                sz = recv(this->sockfd, &recv_buf[0], 16, 0);
                return_buf.insert(std::end(return_buf), std::begin(recv_buf), std::end(recv_buf));
        } while (sz > 0);
        return return_buf;
}

std::string socket::recv_str(void) {
        ssize_t sz = 0;
        char recv_buf[16];
        std::stringstream iss;
        do {
                memset(recv_buf, 0, 16);
                sz = ::recv(this->sockfd, recv_buf, 16, 0);
                iss << recv_buf;
        } while (sz > 0);
        for (auto c : iss.str()) {
                std::cout << "0x" << std::setw(2) << std::setfill('0') << std::hex << (int) c << std::endl;
        }
        return iss.str();
}

bool socket::valid_port(uint32_t port) {
        if (port < 1 || port > 65535) {
                return false;
        }
        return true;
}