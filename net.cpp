// (C) 2021-2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <string>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

// TODO: error checking

int create_datagram_socket(const int port)
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd == -1)
		return -1;

	struct sockaddr_in a { 0 };
        a.sin_family      = PF_INET;
        a.sin_port        = htons(port);
        a.sin_addr.s_addr = htonl(INADDR_ANY);

	if (bind(fd, reinterpret_cast<const struct sockaddr *>(&a), sizeof(a)) == -1) {
		close(fd);

		return -1;
	}

	return fd;
}

int get_local_port(const int fd)
{
	struct sockaddr a { 0 };
	socklen_t       a_len { sizeof a };

	getsockname(fd, &a, &a_len);

	return ntohs(reinterpret_cast<const struct sockaddr_in *>(&a)->sin_port);
}

std::string sockaddr_to_str(const struct sockaddr_in & a)
{
	struct sockaddr_in addr = a;  // inet_ntoa doesn't want const

	return inet_ntoa(addr.sin_addr);
}
