// (C) 2021-2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <optional>
#include <string>
#include <sys/socket.h>


int         create_datagram_socket(const int port);
std::optional<std::pair<int, std::pair<std::string, int> > > create_datagram_socket_for(const int local_port, const struct sockaddr_in & target_addr);

std::string sockaddr_to_str(const struct sockaddr_in & a);

std::pair<std::string, int>       get_local_addr(const int fd);

std::optional<struct sockaddr_in> find_interface_for(const std::string & ip);

std::optional<struct sockaddr>    resolve_name(const std::string & name, const int port = 5060);

std::optional<std::string>        get_host_as_text(struct sockaddr *const a);
