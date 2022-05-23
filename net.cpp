// (C) 2021-2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <optional>
#include <string>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

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

	if (getsockname(fd, &a, &a_len) == -1)
		return -1;

	return ntohs(reinterpret_cast<const struct sockaddr_in *>(&a)->sin_port);
}

std::string sockaddr_to_str(const struct sockaddr_in & a)
{
	struct sockaddr_in addr = a;  // inet_ntoa doesn't want const

	return inet_ntoa(addr.sin_addr);
}

std::optional<struct sockaddr_in> find_interface_for(const std::string & ip)
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd == -1)
		return { };

	struct sockaddr_in target { 0 };

        target.sin_family      = PF_INET;
        target.sin_port        = htons(5060);  // any should do
        target.sin_addr.s_addr = inet_addr(ip.c_str());

	if (connect(fd, reinterpret_cast<const sockaddr *>(&target), sizeof target) == -1) {
		close(fd);

		return { };
	}

	struct sockaddr a { 0 };
	socklen_t       a_len { sizeof a };

	if (getsockname(fd, &a, &a_len) == -1) {
		close(fd);

		return { };
	}

	close(fd);

	return *reinterpret_cast<struct sockaddr_in *>(&a);
}
