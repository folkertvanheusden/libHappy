// (C) 2021-2023 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <optional>
#include <string>
#include <sys/socket.h>


int                         create_datagram_socket(const int port);
std::optional<std::pair<int, std::pair<std::string, int> > > create_datagram_socket_for(const int local_port, const sockaddr_in & target_addr);

std::string                 sockaddr_to_str(const sockaddr_in & a);

std::pair<std::string, int> get_local_addr(const int fd);

std::optional<sockaddr_in>  find_interface_for(const std::string & ip);

std::optional<sockaddr>     resolve_name(const std::string & name, const int port = 5060);

std::optional<std::string>  get_host_as_text(sockaddr *const a);
