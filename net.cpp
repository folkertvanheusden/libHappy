// (C) 2021-2023 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <errno.h>
#include <netdb.h>
#include <optional>
#include <string>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "utils.h"


int create_datagram_socket(const int port)
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd == -1)
		return -1;

	sockaddr_in a { 0 };
        a.sin_family      = PF_INET;
        a.sin_port        = htons(port);
        a.sin_addr.s_addr = htonl(INADDR_ANY);

	if (bind(fd, reinterpret_cast<const sockaddr *>(&a), sizeof(a)) == -1) {
		close(fd);

		DOLOG(ll_error, "Cannot bind to port %d: %s\n", port, strerror(errno));

		return -1;
	}

	return fd;
}

std::string sockaddr_to_str(const sockaddr_in & a)
{
	sockaddr_in addr = a;  // inet_ntoa doesn't want const

	return inet_ntoa(addr.sin_addr);
}

std::pair<std::string, int> get_local_addr(const int fd)
{
	sockaddr  a     { 0        };
	socklen_t a_len { sizeof a };

	if (getsockname(fd, &a, &a_len) == -1)
		return { "", -1 };

	return {
		sockaddr_to_str(*reinterpret_cast<const sockaddr_in *>(&a)),

		ntohs(reinterpret_cast<const sockaddr_in *>(&a)->sin_port)
		};
}

std::optional<sockaddr_in> find_interface_for(const std::string & ip)
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd == -1)
		return { };

	sockaddr_in target { 0 };

        target.sin_family      = PF_INET;
        target.sin_port        = htons(5060);  // any should do
        target.sin_addr.s_addr = inet_addr(ip.c_str());

	if (connect(fd, reinterpret_cast<const sockaddr *>(&target), sizeof target) == -1) {
		close(fd);

		return { };
	}

	sockaddr  a     { 0        };
	socklen_t a_len { sizeof a };

	if (getsockname(fd, &a, &a_len) == -1) {
		close(fd);

		return { };
	}

	close(fd);

	return *reinterpret_cast<sockaddr_in *>(&a);
}

std::optional<std::pair<int, std::pair<std::string, int> > > create_datagram_socket_for(const int local_port, const sockaddr_in & target_addr)
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd == -1)
		return { };

	if (connect(fd, reinterpret_cast<const sockaddr *>(&target_addr), sizeof target_addr) == -1) {
		close(fd);

		return { };
	}

	auto local_addr = get_local_addr(fd);

	if (local_addr.second == -1) {
		close(fd);

		return { };
	}

	return { { fd, local_addr } };
}

std::optional<sockaddr> resolve_name(const std::string & name, const int port)
{
	addrinfo hints { 0 };

	hints.ai_family    = AF_UNSPEC;    // Allow IPv4 or IPv6
	hints.ai_socktype  = SOCK_DGRAM;
	hints.ai_flags     = AI_PASSIVE;    // For wildcard IP address
	hints.ai_protocol  = 0;          // Any protocol
	hints.ai_canonname = nullptr;
	hints.ai_addr      = nullptr;
	hints.ai_next      = nullptr;

	char portnr_str[8] { 0 };
	snprintf(portnr_str, sizeof portnr_str, "%d", port);

	addrinfo *result { nullptr };

	int rc = getaddrinfo(name.c_str(), portnr_str, &hints, &result);
	if (rc != 0) {
		DOLOG(info, "Problem resolving %s: %s\n", name.c_str(), gai_strerror(rc));

		return { };
	}

	for(addrinfo *rp = result; rp != nullptr; rp = rp->ai_next) {
		int fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (fd == -1)
			continue;

		int rc = connect(fd, rp->ai_addr, rp->ai_addrlen);

		close(fd);

		if (rc == 0) {
			sockaddr temp = *rp->ai_addr;

			freeaddrinfo(result);

			return temp;
		}
	}

	freeaddrinfo(result);

	return { };
}

std::optional<std::string> get_host_as_text(sockaddr *const a)
{
	char buffer[INET6_ADDRSTRLEN > INET_ADDRSTRLEN ? INET6_ADDRSTRLEN : INET_ADDRSTRLEN] { 0 };

	if (a->sa_family == AF_INET6) {
		sockaddr_in6 *addr_in6 = reinterpret_cast<sockaddr_in6 *>(a);

		if (!inet_ntop(a->sa_family, &addr_in6->sin6_addr, buffer, INET6_ADDRSTRLEN)) {
			DOLOG(info, "Problem converting sockaddr: %s\n", strerror(errno));

			return { };
		}
	}
	else if (a->sa_family == AF_INET) {
		sockaddr_in *addr_in = reinterpret_cast<sockaddr_in *>(a);

		if (!inet_ntop(a->sa_family, &addr_in->sin_addr, buffer, INET_ADDRSTRLEN)) {
			DOLOG(info, "Problem converting sockaddr: %s\n", strerror(errno));

			return { };
		}
	}
	else {
		DOLOG(warning, "Unsupported address family %d\n", a->sa_family);

		return { };
	}

	return buffer;
}
