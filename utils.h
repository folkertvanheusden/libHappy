// (C) 2020-2023 by folkert van heusden <mail@vanheusden.com>, CC0 license

#pragma once
#include <optional>
#include <stdint.h>
#include <string>
#include <vector>

uint64_t    get_us();
uint64_t    get_ms();
void        myusleep(uint64_t us);

void        get_random(uint8_t *tgt, size_t n);
std::string random_hex(const size_t n);

std::string                myformat(const char *const fmt, ...);
std::vector<std::string>   split(std::string in, std::string splitter);
std::string                replace(std::string target, const std::string & what, const std::string & by_what);
std::string                merge(const std::vector<std::string> & in, const std::string & seperator);
std::string                str_tolower(std::string s);
std::optional<std::string> find_header(const std::vector<std::string> *const lines, const std::string & key, const std::string & seperator = ":");

typedef enum { debug, info, warning, ll_error } log_level_t;  // TODO ll_ prefix
void setlog(const char *lf, const log_level_t ll_file, const log_level_t ll_screen);
void setloguid(const int uid, const int gid);
void closelog();
void dolog(const log_level_t ll, const char *fmt, ...);
#define DOLOG(ll, fmt, ...) do {				\
	extern log_level_t log_level_file, log_level_screen;	\
								\
	if (ll >= log_level_file || ll >= log_level_screen)	\
		dolog(ll, fmt, ##__VA_ARGS__);			\
	} while(0)

void set_thread_name(std::string name);

void error_exit(const bool se, const char *format, ...);
