// (C) 2020-2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <cstring>
#include <math.h>
#include <optional>
#include <poll.h>
#include <samplerate.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <speex/speex.h>
#include <sys/time.h>

#include "net.h"
#include "sip.h"
#include "utils.h"


typedef struct {
	void *state;
	SpeexBits bits;
} speex_t;

static void resample(SRC_STATE *const state, const short *const in, const int in_rate, const int n_samples, short **const out, const int out_rate, int *const out_n_samples)
{
	float *in_float = new float[n_samples];
	src_short_to_float_array(in, in_float, n_samples);

	double ratio = out_rate / double(in_rate);
	*out_n_samples = n_samples * ratio;
	float *out_float = new float[*out_n_samples];

	SRC_DATA sd;
	sd.data_in = in_float;
	sd.data_out = out_float;
	sd.input_frames = n_samples;
	sd.output_frames = *out_n_samples;
	sd.input_frames_used = 0;
	sd.output_frames_gen = 0;
	sd.end_of_input = 0;
	sd.src_ratio = ratio;

	// TODO: src_process gebruiken en dan end_of_input op 0 laten(!)

	int rc = -1;
	if ((rc = src_process(state, &sd)) != 0)
		DOLOG(warning, "SIP: resample failed: %s", src_strerror(rc));

	*out = new short[*out_n_samples];
	src_float_to_short_array(out_float, *out, *out_n_samples);

	delete [] out_float;

	delete [] in_float;
}

// from
// http://dystopiancode.blogspot.com/2012/02/pcm-law-and-u-law-companding-algorithms.html
static int8_t encode_alaw(int16_t number)
{
	uint16_t mask = 0x800;
	uint8_t sign = 0;
	uint8_t position = 11;
	uint8_t lsb = 0;

	if (number < 0) {
		number = -number;
		sign = 0x80;
	}

	number >>= 4; // 16 -> 12

	for(; ((number & mask) != mask && position >= 5); mask >>= 1, position--);

	lsb = (number >> ((position == 4) ? (1) : (position - 4))) & 0x0f;

	return (sign | ((position - 4) << 4) | lsb) ^ 0x55;
}

sip::sip(const std::string & upstream_sip_server, const std::string & upstream_sip_user, const std::string & upstream_sip_password,
		const std::string & myip, const int myport,
		const int sip_register_interval, const int samplerate,
		std::function<bool(sip_session_t *const session)> new_session_callback,
		std::function<bool(const short *const samples, const size_t n_samples, sip_session_t *const session)> recv_callback,
		std::function<bool(short **const samples, size_t *const n_samples, sip_session_t *const session)> send_callback,
		std::function<void(sip_session_t *const session)> end_session_callback) :
	upstream_server(upstream_sip_server), username(upstream_sip_user), password(upstream_sip_password),
	myip(myip), myport(myport),
	interval(sip_register_interval),
	samplerate(samplerate),
	new_session_callback(new_session_callback), recv_callback(recv_callback), send_callback(send_callback), end_session_callback(end_session_callback)
{
	th1 = new std::thread(&sip::session_cleaner, this);  // session cleaner

	sip_fd = create_datagram_socket(5060);

	th2 = new std::thread(&sip::register_thread, this);  // keep-alive to upstream SIP

	th3 = new std::thread(&sip::sip_listener, this);  // listens for SIP packets
}

sip::~sip()
{
	stop_flag = true;

	th3->join();
	delete th3;

	th2->join();
	delete th2;

	th1->join();
	delete th1;
}

void sip::sip_listener()
{
	struct pollfd fds[] { { sip_fd, POLLIN, 0 } };

	for(;!stop_flag;) {
		uint8_t buffer[1600] { 0 };

		int rc = poll(fds, 1, 500);

		if (rc == -1)
			break;

		if (rc == 1) {
			sockaddr_in addr     { 0 };
			socklen_t   addr_len { sizeof addr };

			ssize_t rc = recvfrom(sip_fd, buffer, sizeof buffer, 0, reinterpret_cast<struct sockaddr *>(&addr), &addr_len);

			if (rc > 0)
				sip_input(&addr, sip_fd, buffer, rc);
		}
	}
}

void sip::sip_input(const sockaddr_in *const a, const int fd, uint8_t *const payload, const size_t payload_size)
{
	if (payload_size == 0)
		return;

	std::string              pl_str       = std::string((const char *)payload, payload_size);

	std::vector<std::string> header_body  = split(pl_str, "\r\n\r\n");

	std::vector<std::string> header_lines = split(header_body.at(0), "\r\n");

	std::vector<std::string> parts        = split(header_lines.at(0), " ");

	uint64_t now = get_us();

	if (parts.size() == 3 && parts.at(0) == "OPTIONS" && parts.at(2) == "SIP/2.0") {
		reply_to_OPTIONS(a, fd, &header_lines);
	}
	else if (parts.size() == 3 && parts.at(0) == "INVITE" && parts.at(2) == "SIP/2.0" && header_body.size() == 2) {
		std::vector<std::string> body_lines = split(header_body.at(1), "\r\n");

		reply_to_INVITE(a, fd, &header_lines, &body_lines);
	}
	else if (parts.size() == 3 && parts.at(0) == "BYE" && parts.at(2) == "SIP/2.0") {
		send_ACK(a, fd, &header_lines);
	}
	else if (parts.size() >= 2 && parts.at(0) == "SIP/2.0" && parts.at(1) == "401") {
		if (now - ddos_protection > 1000000) {
			reply_to_UNAUTHORIZED(a, fd, &header_lines);
			ddos_protection = now;
		}
		else {
			DOLOG(info, "SIP: drop 401 packet\n");
		}
	}
	else {
		DOLOG(info, "SIP: request \"%s\" not understood\n", header_lines.at(0).c_str());
	}
}

static void create_response_headers(const std::string & request, std::vector<std::string> *const target, const bool upd_cseq, const std::vector<std::string> *const source, const size_t c_size, const sockaddr_in & a, const std::string & myip)
{
	target->push_back(request);

	auto str_via     = find_header(source, "Via");
	auto str_from    = find_header(source, "From");
	auto str_to      = find_header(source, "To");
	auto str_call_id = find_header(source, "Call-ID");
	auto str_cseq    = find_header(source, "CSeq");

	if (str_via.has_value())
		target->push_back("Via: " + str_via.value());

	if (str_from.has_value())
		target->push_back("From: " + str_from.value());

	if (str_to.has_value())
		target->push_back("To: " + str_to.value());

	if (str_call_id.has_value())
		target->push_back("Call-ID: " + str_call_id.value());

	if (str_cseq.has_value()) {
		if (upd_cseq) {
			std::string request_method = request.substr(0, request.find(' '));

			int cseq = str_cseq.has_value() ? atoi(str_cseq.value().c_str()) : 0;

			target->push_back(myformat("CSeq: %u %s", cseq + 1, request_method.c_str()));
		}
		else {
			target->push_back("CSeq: " + str_cseq.value());
		}
	}

	target->push_back(myformat("Server: %s", myip.c_str()));

	//target->push_back("Allow: INVITE, ASK, CANCEL, OPTIONS, BYE");
	target->push_back("Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, SUBSCRIBE, NOTIFY, INFO, PUBLISH, MESSAGE");

	if (str_to.has_value()) {
		std::string::size_type lt = str_to.value().rfind('<');
		std::string::size_type gt = str_to.value().rfind('>');

		if (lt != std::string::npos && gt != std::string::npos) {
			std::string contact = str_to.value().substr(lt, gt - lt + 1);

			target->push_back(myformat("Contact: %s", contact.c_str()));
		}
	}

	target->push_back("User-Agent: libHappy");

	if (c_size > 0)
		target->push_back("Content-Type: application/sdp");

	target->push_back(myformat("Content-Length: %zu", c_size));
}

bool sip::transmit_packet(const sockaddr_in *const a, const int fd, const uint8_t *const data, const size_t data_size)
{
	return sendto(fd, data, data_size, MSG_CONFIRM, reinterpret_cast<const struct sockaddr *>(a), sizeof *a) == ssize_t(data_size);
}

void sip::reply_to_OPTIONS(const sockaddr_in *const a, const int fd, const std::vector<std::string> *const headers)
{
	std::string proto = a->sin_family == AF_INET ? "IP4" : "IP6";

	std::vector<std::string> content;
	content.push_back("v=0");
	content.push_back("o=jdoe 0 0 IN " + proto + " " + sockaddr_to_str(*a).c_str()); // my ip
	content.push_back("c=IN " + proto + " " + sockaddr_to_str(*a).c_str()); // my ip
	content.push_back("s=Happy");
	content.push_back("t=0 0");
	// 1234 could be allocated but as this is send-
	// only, it is not relevant
	content.push_back("m=audio 1234 RTP/AVP 8 11 97");
	content.push_back("a=sendrecv");
	content.push_back(myformat("a=rtpmap:8 PCMA/%u", samplerate));
	content.push_back(myformat("a=rtpmap:11 L16/%u", samplerate));
	content.push_back(myformat("a=rtpmap:97 speex/%u", samplerate));
	content.push_back("a=fmtp:97 mode=\"1,any\";vbr=on");

	std::string content_out = merge(content, "\r\n");

	std::vector<std::string> hout;
	create_response_headers("SIP/2.0 200 OK", &hout, false, headers, content_out.size(), *a, myip);
	std::string headers_out = merge(hout, "\r\n");

	std::string out = headers_out + "\r\n" + content_out;

	if (transmit_packet(a, fd, (const uint8_t *)out.c_str(), out.size()) == false)
		DOLOG(info, "sip::reply_to_OPTIONS: transmit failed");
}

codec_t select_schema(const std::vector<std::string> *const body, const int max_rate)
{
	codec_t best { 255, "", "", -1 };

	for(std::string line : *body) {
		if (line.substr(0, 9) != "a=rtpmap:")
			continue;

		std::string pars = line.substr(9);

		std::size_t lspace = pars.find(' ');
		if (lspace == std::string::npos)
			continue;

		std::string type_rate = pars.substr(lspace + 1);

		std::size_t slash = type_rate.find('/');
		if (slash == std::string::npos)
			continue;

		uint8_t id = atoi(pars.substr(0, lspace).c_str());

		std::string name = str_tolower(type_rate.substr(0, slash));
		int rate = atoi(type_rate.substr(slash + 1).c_str());

		bool pick = false;

		if (rate >= best.rate && (name == "l16" || name.substr(0, 5) == "speex" || name == "alaw" || name == "pcma")) {
			if (abs(rate - max_rate) < abs(rate - best.rate) || best.rate == -1)
				pick = true;
		}
		else if (rate == best.rate) {
			if (name == "l16")
				pick = true;
			else if (name != "l16" && name.substr(0, 5) == "speex")
				pick = true;
			else if (best.id == 255)
				pick = true;
		}

		if (pick && name.substr(0, 5) != "speex") {
			best.rate = rate;
			best.id = id;
			best.name = name;
			best.org_name = type_rate.substr(0, slash);
		}
	}

	if (best.id == 255) {
		DOLOG(info, "SIP: no suitable codec found? picking sane default\n");

		best.id       = 8;
		best.name     = "pcma";  // safe choice
		best.org_name = "PCMA";  // safe choice
		best.rate     = 8000;
	}

	if (best.name.substr(0, 5) == "speex") {
		void *enc_state = speex_encoder_init(&speex_nb_mode);
		speex_encoder_ctl(enc_state,SPEEX_GET_FRAME_SIZE, &best.frame_size);
		speex_encoder_destroy(enc_state);
	}
	else {
		// usually 20ms
		best.frame_size = best.rate * 20 / 1000;
	}

	DOLOG(info, "SIP: CODEC chosen: %s/%d (id: %u), frame size: %d\n", best.name.c_str(), best.rate, best.id, best.frame_size);

	return best;
}

void sip::reply_to_INVITE(const sockaddr_in *const a, const int fd, const std::vector<std::string> *const headers, const std::vector<std::string> *const body)
{
	std::string proto = a->sin_family == AF_INET ? "IP4" : "IP6";

	std::vector<std::string> content;
	content.push_back("v=0");
	content.push_back("o=jdoe 0 0 IN " + proto + " " + myip.c_str());
	content.push_back("c=IN " + proto + " " + myip.c_str());
	content.push_back("s=Happy");
	content.push_back("t=0 0");

	auto m = find_header(body, "m", "=");

	if (m.has_value()) {
		std::vector<std::string> m_parts = split(m.value(), " ");

		codec_t schema = select_schema(body, samplerate);

		if (schema.id != 255) {
			// find port to transmit rtp data to and start send-thread
			int tgt_rtp_port = m_parts.size() >= 2 ? atoi(m_parts.at(1).c_str()) : 8000;

			sip_session_t *ss  = new sip_session_t();
			ss->start_ts       = get_us();
			ss->headers        = *headers;
			memcpy(&ss->sip_addr_peer, a, sizeof ss->sip_addr_peer);
			ss->schema         = schema;
			ss->fd             = create_datagram_socket(0);
			ss->audio_port     = get_local_port(ss->fd);

			int dummy = 0;
			ss->audio_in_resample  = src_new(SRC_SINC_BEST_QUALITY, 1, &dummy);  // TODO error checking
			src_set_ratio(ss->audio_in_resample, double(samplerate) / schema.rate);  // TODO error checking

			ss->audio_out_resample = src_new(SRC_SINC_BEST_QUALITY, 1, &dummy);  // TODO error checking
			src_set_ratio(ss->audio_out_resample, schema.rate / double(samplerate));  // TODO error checking

			content.push_back("a=sendrecv");
			content.push_back(myformat("a=rtpmap:%u %s/%u", schema.id, schema.org_name.c_str(), schema.rate));

			if (schema.name.substr(0, 5) == "speex")
				content.push_back(myformat("a=fmtp:%u mode=\"1,any\";vbr=on", schema.id));
			
			content.push_back(myformat("m=audio %d RTP/AVP %u", ss->audio_port, schema.id));

			std::string content_out = merge(content, "\r\n");

			// merge headers
			std::vector<std::string> hout;
			create_response_headers("SIP/2.0 200 OK", &hout, false, headers, content_out.size(), ss->sip_addr_peer, myip);
			std::string headers_out = merge(hout, "\r\n");

			std::string out = headers_out + "\r\n" + content_out;

			// send INVITE reply
			if (transmit_packet(a, fd, (const uint8_t *)out.c_str(), out.size()) == false)
				DOLOG(info, "sip::reply_to_INVITE: transmit failed");

			new_session_callback(ss);

			std::thread *th = new std::thread(&sip::session, this, *a, tgt_rtp_port, ss);

			slock.lock();
			sessions.insert({ th, ss });
			slock.unlock();
		}
	}
}

void sip::send_ACK(const sockaddr_in *const a, const int fd, const std::vector<std::string> *const headers)
{
	std::vector<std::string> hout;
	create_response_headers("SIP/2.0 200 OK", &hout, false, headers, 0, *a, myip);

	std::string out = merge(hout, "\r\n");

	if (transmit_packet(a, fd, (const uint8_t *)out.c_str(), out.size()) == false)
		DOLOG(info, "sip::send_ACK: transmit failed");
}

void sip::reply_to_UNAUTHORIZED(const sockaddr_in *const a, const int fd, const std::vector<std::string> *const headers)
{
	auto str_wa = find_header(headers, "WWW-Authenticate");
	if (!str_wa.has_value()) {
		DOLOG(info, "SIP: \"WWW-Authenticate\" missing");
		return;
	}

	auto call_id = find_header(headers, "Call-ID");

	std::string work = replace(str_wa.value(), ",", " ");

	std::vector<std::string> parameters = split(work, " ");

	std::string digest_alg = "MD5";
	auto str_da = find_header(&parameters, "algorithm", "=");
	if (str_da.has_value())
		digest_alg = str_da.value();

	std::string realm = "";
	auto str_realm = find_header(&parameters, "realm", "=");
	if (str_realm.has_value())
		realm = replace(str_realm.value(), "\"", "");

	std::string nonce = "";
	auto str_nonce = find_header(&parameters, "nonce", "=");
	if (str_nonce.has_value())
		nonce = replace(str_nonce.value(), "\"", "");

	std::string a1 = md5hex(username + ":" + realm + ":" + password);
	std::string a2 = md5hex("REGISTER:sip:" + myip);

	std::string digest = md5hex(a1 + ":" + nonce + ":" + a2);

	std::string authorize = "Authorization: Digest username=\"" + username + "\",realm=\"" + realm + "\",nonce=\"" + nonce + "\",uri=\"sip:" + myip + "\",algorithm=MD5,response=\"" + digest + "\"";

	std::string call_id_str = call_id.has_value() ? call_id.value() : "";

	send_REGISTER(call_id_str, authorize);
}

static std::pair<uint8_t *, int> create_rtp_packet(const uint32_t ssrc, const uint16_t seq_nr, const uint32_t t, const codec_t & schema, const short *const samples, const int n_samples)
{
	int sample_size = 0;

	if (schema.name == "alaw" || schema.name == "pcma")// a-law
		sample_size = sizeof(uint8_t);
	else if (schema.name == "l16")	// l16 mono
		sample_size = sizeof(uint16_t);
	else if (schema.name.substr(0, 5) == "speex")	// speex
		sample_size = sizeof(uint8_t);
	else {
		DOLOG(ll_error, "SIP: Invalid rtp payload schema %s/%d\n", schema.name.c_str(), schema.rate);
		return { nullptr, 0 };
	}

	size_t size = 3 * 4 + n_samples * sample_size;
	uint8_t *rtp_packet = new uint8_t[size * 2](); // *2 for speex (is this required?)

	rtp_packet[0] |= 128;  // v2
	rtp_packet[1] = schema.id;
	rtp_packet[2] = seq_nr >> 8;
	rtp_packet[3] = seq_nr;
	rtp_packet[4] = t >> 24;
	rtp_packet[5] = t >> 16;
	rtp_packet[6] = t >>  8;
	rtp_packet[7] = t;
	rtp_packet[8] = ssrc >> 24;
	rtp_packet[9] = ssrc >> 16;
	rtp_packet[10] = ssrc >>  8;
	rtp_packet[11] = ssrc;

	if (schema.name == "alaw" || schema.name == "pcma") {	// a-law
		for(int i=0; i<n_samples; i++)
			rtp_packet[12 + i] = encode_alaw(samples[i]);
	}
	else if (schema.name == "l16") {	// l16 mono
		for(int i=0; i<n_samples; i++) {
			rtp_packet[12 + i * 2 + 0] = samples[i] >> 8;
			rtp_packet[12 + i * 2 + 1] = samples[i];
		}
	}
	else if (schema.name.substr(0, 5) == "speex") { // speex
		speex_t spx { 0 };

		speex_bits_init(&spx.bits);
		speex_bits_reset(&spx.bits);

		spx.state = speex_encoder_init(&speex_nb_mode);

		int tmp = 10;
		speex_encoder_ctl(spx.state, SPEEX_SET_QUALITY, &tmp);

		// is this required?
		short *input = new short[n_samples];
		memcpy(input, samples, n_samples * sizeof(short));

		speex_encode_int(spx.state, input, &spx.bits);

		size_t new_size = 12 + speex_bits_write(&spx.bits, (char *)&rtp_packet[12], size - 12);

		delete [] input;

		speex_encoder_destroy(spx.state);
		speex_bits_destroy(&spx.bits);

		if (new_size > size) {
			DOLOG(ll_error, "SIP: speex decoded data too big (%ld > %ld)\n", new_size, size);
			delete [] rtp_packet;
			return { nullptr, 0 };
		}

		size = new_size;
	}

	return { rtp_packet, size };
}

void sip::send_BYE(const sockaddr_in *const a, const int fd, const std::vector<std::string> & headers)
{
	std::string number = "0";

	auto str_to = find_header(&headers, "To");
	if (str_to.has_value()) {
		std::string::size_type lt = str_to.value().rfind('<');
		std::string::size_type gt = str_to.value().rfind('>');

		if (lt != std::string::npos && gt != std::string::npos)
			number = str_to.value().substr(lt + 1, gt - lt - 1);
	}

	std::vector<std::string> hout;
	create_response_headers(myformat("BYE %s SIP/2.0", number.c_str()), &hout, true, &headers, 0, *a, myip);

	std::string out = merge(hout, "\r\n") + "\r\n";

	if (transmit_packet(a, fd, (const uint8_t *)out.c_str(), out.size()) == false)
		DOLOG(info, "sip::send_BYTE: transmit failed");
}

bool sip::transmit_audio(const sockaddr_in tgt_addr, sip_session_t *const ss, const short *const audio_in, const int n_audio_in, uint16_t *const seq_nr, uint32_t *const t, const uint32_t ssrc)
{
	int offset = 0;

	int    n_audio = 0;
	short *audio   = nullptr;

	if (samplerate == ss->schema.rate) {
		n_audio = n_audio_in;
		audio   = (short *)audio_in;  // FIXME
	}
	else {
		resample(ss->audio_out_resample, audio_in, samplerate, n_audio_in, &audio, ss->schema.rate, &n_audio);
	}

	while(n_audio > 0 && !stop_flag && !ss->stop_flag) {
		int cur_n_before = std::min(n_audio, ss->schema.frame_size);
		std::pair<uint8_t *, int> rtpp;

		bool odd = cur_n_before & 1;
		rtpp = create_rtp_packet(ssrc, *seq_nr, *t, ss->schema, &audio[offset], cur_n_before + odd);

		offset += cur_n_before;
		n_audio -= cur_n_before;

		(*t) += cur_n_before;

		(*seq_nr)++;

		if (rtpp.second) {
			if (transmit_packet(&tgt_addr, ss->fd, rtpp.first, rtpp.second) == false) {
				DOLOG(info, "sip::send_BYTE: transmit failed");

				return false;
			}

			delete [] rtpp.first;
		}

		double sleep = 1000000.0 / (samplerate / double(cur_n_before));
		myusleep(sleep);
	}

	if (samplerate != ss->schema.rate)
		delete [] audio;

	return true;
}

void sip::wait_for_audio(sip_session_t *const ss)
{
	DOLOG(info, "sip::wait_for_audio: audio receive handler thread started\n");

	// wait for packets on ss->fd
	// send them to audio_input()
	struct pollfd fds[] { { ss->fd, POLLIN, 0 } };

	for(;!stop_flag && !ss->stop_flag;) {
		uint8_t buffer[1600] { 0 };

		int rc = poll(fds, 1, 500);

		if (rc == -1)
			break;

		if (rc == 1) {
			sockaddr_in addr     { 0 };
			socklen_t   addr_len { sizeof addr };

			ssize_t rc = recvfrom(ss->fd, buffer, sizeof buffer, 0, reinterpret_cast<struct sockaddr *>(&addr), &addr_len);

			if (rc > 0) {
				DOLOG(debug, "sip::wait_for_audio: audio received (%zd bytes) from %s:%d\n", rc, sockaddr_to_str(addr).c_str(), ntohs(addr.sin_port));

				audio_input(buffer, rc, ss);
			}
		}
	}
}

void generate_beep(const double f, const double duration, const int samplerate, short **const beep, size_t *const beep_n)
{
	*beep_n = samplerate * duration;
	*beep = new short[*beep_n];

	double mul = 2.0 * M_PI * f;

	for(size_t i=0; i<*beep_n; i++)
		(*beep)[i] = 32767 * sin(mul * (i + i / double(samplerate)));
}

void sip::session(const struct sockaddr_in tgt_addr, const int tgt_rtp_port, sip_session_t *const ss)
{
	set_thread_name("SIP-RTP");

	struct sockaddr_in work_addr = tgt_addr;
	work_addr.sin_port = htons(tgt_rtp_port);

	DOLOG(info, "sip::session: session handler thread started. transmit to %s:%d\n", sockaddr_to_str(work_addr).c_str(), tgt_rtp_port);

	std::thread audio_recv_thread([this, ss]() { wait_for_audio(ss); });

	uint16_t seq_nr = 0;
	uint32_t t      = 0;

	uint32_t ssrc   = 0;
	get_random((uint8_t *)&ssrc, sizeof ssrc);

	for(;!stop_flag && !ss->stop_flag;) {
		short *samples = nullptr;
		size_t n_samples = 0;

		if (send_callback(&samples, &n_samples, ss) == false) {
			DOLOG(debug, "sip::session: callback indicated end\n");

			break;
		}

		if (transmit_audio(work_addr, ss, samples, n_samples, &seq_nr, &t, ssrc) == false) {
			DOLOG(debug, "sip::session: transmit audio failed\n");

			break;
		}

		delete [] samples;
	}

	ss->stop_flag = true;

	send_BYE(&tgt_addr, ss->fd, ss->headers);

	send_REGISTER("", "");  // required?

	ss->finished  = true;

	DOLOG(info, "sip::session: session handler thread terminated\n");
}

// from
// http://dystopiancode.blogspot.com/2012/02/pcm-law-and-u-law-companding-algorithms.html
static int16_t decode_alaw(int8_t number)
{
	uint8_t sign = 0x00;
	uint8_t position = 0;
	int16_t decoded = 0;

	number^=0x55;

	if (number&0x80) {
		number&=~(1<<7);
		sign = -1;
	}

	position = ((number & 0xF0) >>4) + 4;

	if (position!=4) {
		decoded = ((1<<position)|((number&0x0F)<<(position-4)) |(1<<(position-5)));
	}
	else {
		decoded = (number<<1)|1;
	}

	return sign == 0 ? decoded:-decoded;
}

void sip::audio_input(const uint8_t *const payload, const size_t payload_size, sip_session_t *const ss)
{
	ss->latest_pkt = get_us();

	if (ss->schema.name == "alaw" || ss->schema.name == "pcma") {  // a-law
		int n_samples = payload_size - 12;

		if (n_samples > 0) {
			short *temp = new short[n_samples];

			for(int i=0; i<n_samples; i++)
				temp[i] = decode_alaw(payload[12 + i]);

			short *result   = nullptr;
			int    result_n = 0;
			resample(ss->audio_in_resample, temp, ss->schema.rate, n_samples, &result, samplerate, &result_n);
			printf("%d -> %d | %d/%d\n", n_samples, result_n, ss->schema.rate, samplerate);

			recv_callback(result, result_n, ss);

			delete [] result;

			delete [] temp;
		}
	}
	else if (ss->schema.name == "l16") { // l16 mono
		int n_samples = (payload_size - 12) / 2;

		if (n_samples > 0) {
			const short *samples = (const short *)&payload[12];

			short *result   = nullptr;
			int    result_n = 0;
			resample(ss->audio_in_resample, samples, ss->schema.rate, n_samples, &result, samplerate, &result_n);

			recv_callback(result, result_n, ss);

			delete [] result;
		}
	}
	else if (ss->schema.name.substr(0, 5) == "speex") { // speex
		speex_t spx { 0 };
		speex_bits_init(&spx.bits);
		spx.state = speex_decoder_init(&speex_nb_mode);

		speex_bits_read_from(&spx.bits, (char *)&payload[12], payload_size - 12);

		int frame_size = 0;
		speex_decoder_ctl(spx.state, SPEEX_GET_FRAME_SIZE, &frame_size);

		short *of = new short[frame_size];
		speex_decode_int(spx.state, &spx.bits, of);

		short *result   = nullptr;
		int    result_n = 0;
		resample(ss->audio_in_resample, of, ss->schema.rate, frame_size, &result, samplerate, &result_n);

		recv_callback(result, result_n, ss);

		delete [] result;

		delete [] of;

		speex_bits_destroy(&spx.bits);
		speex_decoder_destroy(spx.state);
	}
	else {
		DOLOG(warning, "SIP: unsupported incoming schema %s/%d\n", ss->schema.name.c_str(), ss->schema.rate);
	}
}

void sip::session_cleaner()
{
	set_thread_name("session-cleaner");

	while(!stop_flag) {
		myusleep(500000);

		slock.lock();
		for(auto it=sessions.begin(); it!=sessions.end();) {
			if (it->second->finished) {
				it->first->join();

				delete it->second;
				delete it->first;

				it = sessions.erase(it);
			}
			else {
				it++;
			}
		}
		slock.unlock();
	}
}

bool sip::send_REGISTER(const std::string & call_id, const std::string & authorize)
{
	int                    tgt_port = 5060;

	std::string            work     = upstream_server;

	std::string::size_type colon    = work.find(':');

	if (colon != std::string::npos) {
		tgt_port = atoi(work.substr(colon + 1).c_str());

		work     = work.substr(0, colon);
	}

	std::string tgt_addr         = work.c_str();

	std::string out = "REGISTER sip:" + tgt_addr + " SIP/2.0\r\n";

	if (authorize.empty()) {
		out += "CSeq: 1 REGISTER\r\n";

		uint64_t r = 0;
		get_random((uint8_t *)&r, sizeof r);

		out += "Call-ID: " + myformat("%08lx", r) + "@" + myip + "\r\n";
	}
       	else {
		out += authorize + "\r\n";
		out += "CSeq: 2 REGISTER\r\n";
		out += "Call-ID: " + call_id + "\r\n";
	}

	out += "Via: SIP/2.0/UDP " + myip + ":" + myformat("%d", myport) + "\r\n";
	out += "User-Agent: Happy\r\n";
	out += "From: <sip:" + username + "@" + tgt_addr + ">;tag=277FD9F0-2607D15D\r\n"; // TODO
	out += "To: <sip:" + username + "@" + tgt_addr + ">\r\n";
	out += "Contact: <sip:" + username + "@" + myip + ">;q=1\r\n";
	out += "Allow: INVITE,ACK,OPTIONS,BYE,CANCEL,SUBSCRIBE,NOTIFY,REFER,MESSAGE,INFO,PING\r\n";
	out += "Expires: 60\r\n";
	out += "Content-Length: 0\r\n";
	out += "Max-Forwards: 70\r\n\r\n";

	struct sockaddr_in a { 0 };
        a.sin_family      = PF_INET;
        a.sin_port        = htons(tgt_port);
        a.sin_addr.s_addr = inet_addr(tgt_addr.c_str());

	return transmit_packet(&a, sip_fd, (const uint8_t *)out.c_str(), out.size());
}

// register at upstream server
void sip::register_thread()
{
	myusleep(2500000);

	while(!stop_flag) {
		int cur_interval = interval;

		if (!send_REGISTER("", ""))
			cur_interval = 30;

		for(int i=0; i<cur_interval * 2 && !stop_flag; i++)
			myusleep(500 * 1000);
	}
}
