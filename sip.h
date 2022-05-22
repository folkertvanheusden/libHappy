// (C) 2020-2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#pragma once
#include <atomic>
#include <functional>
#include <map>
#include <mutex>
#include <samplerate.h>
#include <stdint.h>
#include <string>
#include <thread>
#include <vector>
#include <netinet/in.h>

// not strictly required here but as a convenience for users
// of this library (only need to include this file)
#include "utils.h"


typedef struct {
	uint8_t     id;

	std::string name;
	std::string org_name;

	int         rate;

	int         frame_size;
	int         frame_duration;
} codec_t;

typedef struct _sip_session_ {
	// data for library itself
	std::thread       *th            { nullptr };
	uint64_t           start_ts      { 0 };

	std::atomic_bool   stop_flag     { false };
	std::atomic_bool   finished      { false };

	std::vector<std::string> headers;

	struct sockaddr_in sip_addr_peer { 0 };

	codec_t            schema        { 255, "", "", -1 };

	std::atomic_uint64_t latest_pkt { 0 };

	int                audio_port   { 0 };
	int                fd           { -1 };

	// callback data
	std::string        call_id;

	// samplerate used by callbacks
	int                samplerate  { 0 };
	SRC_STATE         *audio_in_resample  { nullptr };
	SRC_STATE         *audio_out_resample { nullptr };

	void              *private_data { nullptr };

	_sip_session_() {
	}

	virtual ~_sip_session_() {
		src_delete(audio_in_resample);
		src_delete(audio_out_resample);

		close(fd);
	}
} sip_session_t;

class sip
{
private:
	std::atomic_bool  stop_flag { false };

	const std::string upstream_server;
	const std::string username;
	const std::string password;

	const std::string myip;
	const int         myport;

	int               sip_fd { -1 };

	const int interval;

	const int samplerate;

	// called when a new session is started, one can set 'private_data'
	std::function<bool(sip_session_t *const session)> new_session_callback;

	// called when we receive audio from peer
	std::function<bool(const short *const samples, const size_t n_samples, sip_session_t *const session)> recv_callback;

	// called to get audio that will be transmitted to peer
	std::function<bool(short **const samples, size_t *const n_samples, sip_session_t *const session)> send_callback;

	// called when a new session finishes, need to free any 'private_data'
	std::function<void(sip_session_t *const session)> end_session_callback;

	// called when a DTMF event has been received
	std::function<void(const uint8_t code, const bool is_end, const uint8_t volume, sip_session_t *const session)> dtmf_callback;

	std::thread *th1 { nullptr };
	std::thread *th2 { nullptr };
	std::thread *th3 { nullptr };

	std::map<std::string, sip_session_t *> sessions;
	std::mutex slock;

	uint64_t ddos_protection { 0 };

	bool transmit_packet(const sockaddr_in *const a, const int fd, const uint8_t *const data, const size_t data_size);

	void reply_to_OPTIONS(const sockaddr_in *const a, const int fd, const std::vector<std::string> *const headers);

	void reply_to_INVITE(const sockaddr_in *const a, const int fd, const std::vector<std::string> *const headers, const std::vector<std::string> *const body);

	void send_BYE(const sockaddr_in *const a, const int fd, const std::vector<std::string> & headers);
	void reply_to_BYE(const sockaddr_in *const a, const int fd, const std::vector<std::string> *const headers);

	bool transmit_audio(const sockaddr_in tgt_addr, sip_session_t *const ss, const short *const samples, const int n_samples, uint16_t *const seq_nr, uint32_t *const t, const uint32_t ssrc);

	bool send_REGISTER(const std::string & call_id, const std::string & authorize);
	void register_thread();

	void reply_to_UNAUTHORIZED(const sockaddr_in *const a, const int fd, const std::vector<std::string> *const headers);
	void send_ACK(const sockaddr_in *const a, const int fd, const std::vector<std::string> *const headers);

	void audio_input(const uint8_t *const payload, const size_t payload_size, sip_session_t *const ss);
	void wait_for_audio(sip_session_t*);

	void sip_input(const sockaddr_in *const a, const int fd, uint8_t *const payload, const size_t payload_size);
	void sip_listener();

	void session(const struct sockaddr_in tgt_addr, const int tgt_rtp_port, sip_session_t *const ss);

	void session_cleaner();

	sip(const sip &) = delete;

public:
	sip(const std::string & upstream_sip_server, const std::string & upstream_sip_user, const std::string & upstream_sip_password,
		const std::string & myip, const int myport,
		const int sip_register_interval, const int samplerate,
		std::function<bool(sip_session_t *const session)> new_session_callback,
		std::function<bool(const short *const samples, const size_t n_samples, sip_session_t *const session)> recv_callback,
		std::function<bool(short **const samples, size_t *const n_samples, sip_session_t *const session)> send_callback,
		std::function<void(sip_session_t *const session)> end_session_callback,
		std::function<void(const uint8_t dtmf_code, const bool is_end, const uint8_t volume, sip_session_t *const session)> dtmf_callback);

	virtual ~sip();
};

void generate_beep(const double f, const double duration, const int samplerate, short **const beep, size_t *const beep_n);
