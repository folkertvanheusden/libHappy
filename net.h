// (C) 2021-2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <string>
#include <sys/socket.h>


int create_datagram_socket(const int port);
int get_local_port(const int fd);
std::string sockaddr_to_str(const struct sockaddr_in & a);
