// (C) 2020-2023 by folkert van heusden <mail@vanheusden.com>, CC0 license

#pragma once
#include <atomic>
#include <condition_variable>
#include <functional>
#include <map>
#include <mutex>
#include <samplerate.h>
#include <stdint.h>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>
#include <netinet/in.h>

// not strictly required here but as a convenience for users
// of this library (only need to include this file)
#include "utils.h"

extern "C" {
#include "libg722/g722_decoder.h"
#include "libg722/g722_encoder.h"
}


typedef enum { call_direct, call_indirect } call_via_t;

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

	std::atomic_uint64_t latest_pkt  { 0 };

	int                audio_port    { 0 };
	int                fd            { -1 };

	G722_ENC_CTX      *g722_encoder  { nullptr };
	G722_DEC_CTX      *g722_decoder  { nullptr };

	std::string        call_id;

	std::string        peer;

	// samplerate used by callbacks
	int                samplerate  { 0 };
	SRC_STATE         *audio_in_resample  { nullptr };
	SRC_STATE         *audio_out_resample { nullptr };

	// configurable in the callbacks
	void              *private_data { nullptr };

	// initialized when invoking the constructor
	void              *global_private_data { nullptr };

	_sip_session_() {
	}

	virtual ~_sip_session_() {
		src_delete(audio_in_resample);
		src_delete(audio_out_resample);

		if (g722_encoder)
			g722_encoder_destroy(g722_encoder);

		if (g722_decoder)
			g722_decoder_destroy(g722_decoder);

		if (fd != -1)
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

	std::string       myip;
	int               myport     { 5060 };
	std::string       myaddr;

	int               sip_fd     { -1 };

	const int         interval   { 300 };

	const int         samplerate { 44100 };

	// the one attached to the 'From'-header
	std::string       tag;

	// called when a new session is started, one can set 'private_data'
	std::function<bool(sip_session_t *const session, const std::string & from)> new_session_callback;

	// called when we receive audio from peer
	std::function<bool(const short *const samples, const size_t n_samples, sip_session_t *const session)> recv_callback;

	// called to get audio that will be transmitted to peer
	std::function<bool(short **const samples, size_t *const n_samples, sip_session_t *const session)> send_callback;

	// called when a new session finishes, need to free any 'private_data'
	std::function<void(sip_session_t *const session)> end_session_callback;

	// called when a DTMF event has been received
	std::function<bool(const uint8_t code, const bool is_end, const uint8_t volume, sip_session_t *const session)> dtmf_callback;

	void       *const global_private_data { nullptr };

	std::thread *th1 { nullptr };
	std::thread *th2 { nullptr };
	std::thread *th3 { nullptr };

	std::map<std::string, sip_session_t *> sessions;
	std::map<std::string, std::pair<int, std::vector<std::string> > > sessions_pending;
	std::mutex                             sessions_lock;
	std::condition_variable                sessions_cv;

	std::mutex                             registered_lock;
	std::string                            register_cid;
	std::string                            register_authline;
	std::string                            register_tag;
	bool				       is_registered { false };
	std::condition_variable                registered_cv;

	uint64_t ddos_protection { 0 };

	bool transmit_packet(const sockaddr_in *const a, const int fd, const uint8_t *const data, const size_t data_size, const bool log);

	void reply_to_OPTIONS(const sockaddr_in *const a, const int fd, const std::vector<std::string> *const headers);

	void reply_to_INVITE(const sockaddr_in *const a, const int fd, const std::vector<std::string> *const headers, const std::vector<std::string> *const body);

	void send_BYE_or_CANCEL(const sockaddr_in *const a, const std::vector<std::string> & headers, const bool is_bye);
	void reply_to_BYE(const sockaddr_in *const a, const int fd, const std::vector<std::string> *const headers);

	bool transmit_audio(const sockaddr_in tgt_addr, sip_session_t *const ss, const short *const samples, const int n_samples, uint16_t *const seq_nr, uint32_t *const t, const uint32_t ssrc);

	bool send_REGISTER(const std::string & call_id, const std::string & authorize);
	void register_thread();

	void reply_to_UNAUTHORIZED(const std::vector<std::string> *const headers);
	void send_ACK(const sockaddr_in *const a, const int fd, const std::vector<std::string> *const headers);

	bool audio_input(const uint8_t *const payload, const size_t payload_size, sip_session_t *const ss);
	void wait_for_audio(sip_session_t*);

	void sip_input(const sockaddr_in *const a, const int fd, uint8_t *const payload, const size_t payload_size);
	void sip_listener();

	sip_session_t * allocate_sip_session();

	std::vector<std::string> generate_sdp_payload(const std::string & ip, const std::string & proto, const int rtp_port);

	std::string generate_authorize_header(const std::vector<std::string> *const headers, const std::string & uri, const std::string & method);

	void session(const struct sockaddr_in tgt_addr, sip_session_t *const ss);

	void wait_for_registered();

	void session_cleaner();

	void forget_session(sip_session_t *const ss);

	sip(const sip &) = delete;

public:
	sip(const std::string & upstream_sip_server, const std::string & upstream_sip_user, const std::string & upstream_sip_password,
		const std::optional<std::string> & myip, const int myport,
		const int sip_register_interval, const int samplerate,
		std::function<bool(sip_session_t *const session, const std::string & from)> new_session_callback,
		std::function<bool(const short *const samples, const size_t n_samples, sip_session_t *const session)> recv_callback,
		std::function<bool(short **const samples, size_t *const n_samples, sip_session_t *const session)> send_callback,
		std::function<void(sip_session_t *const session)> end_session_callback,
		std::function<bool(const uint8_t dtmf_code, const bool is_end, const uint8_t volume, sip_session_t *const session)> dtmf_callback,
		void *const global_private_data);

	virtual ~sip();

	// timeout is in seconds
	// if 'direct' is true then the library will connect directly to the peer, not via the 'upstream_sip_server
	std::pair<std::optional<std::string>, int> initiate_call(const std::string & target, const std::string & local_address, const int timeout, const call_via_t via);
};

void generate_beep(const double f, const double duration, const int samplerate, short **const beep, size_t *const beep_n);
