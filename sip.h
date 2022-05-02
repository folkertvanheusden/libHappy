// (C) 2020-2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once
#include <atomic>
#include <map>
#include <mutex>
#include <sndfile.h>
#include <stdint.h>
#include <string>
#include <thread>
#include <vector>

#include "any_addr.h"

typedef struct {
	uint8_t id;
	std::string name, org_name;
	int rate;
	int frame_size;
} codec_t;

typedef struct _sip_session_ {
	uint64_t start_ts { 0 };
	std::atomic_bool finished { false };
	std::vector<std::string> headers;
	any_addr sip_addr_peer, sip_addr_me;
	int sip_port_peer { 0 }, sip_port_me { 0 };
	std::thread *recorder { nullptr };
	codec_t schema { 255, "", "", -1 };
	std::atomic_uint64_t latest_pkt { 0 };
	int audio_port, fd;

	_sip_session_() {
	}

} sip_session_t;

class sip
{
private:
	std::atomic_bool stop_flag { false };

	const std::string upstream_server, username, password;
	const any_addr myip;
	const int myport, interval;
	const int samplerate;

	std::thread *th1 { nullptr };
	std::thread *th2 { nullptr };
	std::thread *th3 { nullptr };

	std::map<std::thread *, sip_session_t *> sessions;
	std::mutex slock;

	uint64_t ddos_protection { 0 };

	void reply_to_OPTIONS(const any_addr & src_ip, const int src_port, const any_addr & dst_ip, const int dst_port, const std::vector<std::string> *const headers);

	void reply_to_INVITE(const any_addr & src_ip, const int src_port, const any_addr & dst_ip, const int dst_port, const std::vector<std::string> *const headers, const std::vector<std::string> *const body);

	void send_BYE(const any_addr & tgt_addr, const int tgt_port, const any_addr & src_addr, const int src_port, const std::vector<std::string> & headers);

	void transmit_audio(const any_addr & tgt_addr, const int tgt_port, const any_addr & src_addr, const int src_port, sip_session_t *const ss, const short *const samples, const int n_samples, uint16_t *const seq_nr, uint32_t *const t, const uint32_t ssrc);

	bool send_REGISTER(const std::string & call_id, const std::string & authorize);
	void register_thread();

	void reply_to_UNAUTHORIZED(const any_addr & src_ip, const int src_port, const any_addr & dst_ip, const int dst_port, const std::vector<std::string> *const headers);
	void send_ACK(const any_addr & src_ip, const int src_port, const any_addr & dst_ip, const int dst_port, const std::vector<std::string> *const headers);

	void audio_input(const any_addr & src_ip, int src_port, const any_addr & dst_ip, int dst_port, const uint8_t *const payload, const size_t payload_size, sip_session_t *const ss);

	void sip_input(const any_addr & src_ip, int src_port, const any_addr & dst_ip, int dst_port, uint8_t *const payload, const size_t payload_size);
	void sip_listener();

	void session(const any_addr & tgt_addr, const int tgt_port, const any_addr & src_addr, const int src_port, sip_session_t *const ss);

public:
	sip(const std::string & upstream_sip_server, const std::string & upstream_sip_user, const std::string & upstream_sip_password, const any_addr & myip, const int myport, const int interval, const int samplerate);
	sip(const sip &) = delete;
	virtual ~sip();

	void operator()();
};
