// (C) 2020-2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <cstring>
#include <math.h>
#include <optional>
#include <poll.h>
#include <samplerate.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include "md5.h"
#include "net.h"
#include "sip.h"
#include "utils.h"


static void resample(SRC_STATE *const state, const short *const in, const int in_rate, const int n_samples, short **const out, const int out_rate, int *const out_n_samples)
{
	float *in_float  = new float[n_samples]();
	src_short_to_float_array(in, in_float, n_samples);

	double ratio     = out_rate / double(in_rate);

	size_t n_out_allocated = ceil(n_samples * ratio);
	float *out_float = new float[n_out_allocated]();

	SRC_DATA sd { 0 };
	sd.data_in           = in_float;
	sd.data_out          = out_float;
	sd.input_frames      = n_samples;
	sd.output_frames     = n_out_allocated;
	sd.input_frames_used = 0;
	sd.output_frames_gen = 0;
	sd.end_of_input      = 0;
	sd.src_ratio         = ratio;

	int rc = -1;
	if ((rc = src_process(state, &sd)) != 0)
		DOLOG(warning, "SIP: resample failed: %s", src_strerror(rc));

	*out_n_samples = sd.output_frames_gen;

	*out = new short[*out_n_samples]();
	src_float_to_short_array(out_float, *out, *out_n_samples);

	delete [] out_float;

	delete [] in_float;
}

// from
// http://dystopiancode.blogspot.com/2012/02/pcm-law-and-u-law-companding-algorithms.html
static int8_t encode_alaw(int16_t number)
{
	uint16_t mask     = 0x800;
	uint8_t  sign     = 0;
	uint8_t  position = 11;
	uint8_t  lsb      = 0;

	if (number < 0) {
		number = -number;
		sign = 0x80;
	}

	number >>= 4; // 16 -> 12

	for(; ((number & mask) != mask && position >= 5); mask >>= 1, position--) {
	}

	lsb = (number >> ((position == 4) ? (1) : (position - 4))) & 0x0f;

	return (sign | ((position - 4) << 4) | lsb) ^ 0x55;
}

static int8_t encode_mulaw(int16_t number)
{
	const uint16_t MULAW_MAX  = 0x1FFF;
	const uint16_t MULAW_BIAS = 33;
	uint16_t mask     = 0x1000;
	uint8_t  sign     = 0;
	uint8_t  position = 12;
	uint8_t  lsb      = 0;

	if (number < 0) {
		number = -number;
		sign = 0x80;
	}

	number += MULAW_BIAS;

	if (number > MULAW_MAX)
		number = MULAW_MAX;

	for (; ((number & mask) != mask && position >= 5); mask >>= 1, position--) {
	}

	lsb = (number >> (position - 4)) & 0x0f;

	return ~(sign | ((position - 5) << 4) | lsb);
}

sip::sip(const std::string & upstream_sip_server, const std::string & upstream_sip_user, const std::string & upstream_sip_password,
		const std::optional<std::string> & myip, const int myport,
		const int sip_register_interval, const int samplerate,
		std::function<bool(sip_session_t *const session, const std::string & from)> new_session_callback,
		std::function<bool(const short *const samples, const size_t n_samples, sip_session_t *const session)> recv_callback,
		std::function<bool(short **const samples, size_t *const n_samples, sip_session_t *const session)> send_callback,
		std::function<void(sip_session_t *const session)> end_session_callback,
		std::function<bool(const uint8_t dtmf_code, const bool is_end, const uint8_t volume, sip_session_t *const session)> dtmf_callback,
		void *const global_private_data) :
	upstream_server(upstream_sip_server), username(upstream_sip_user), password(upstream_sip_password),
	interval(sip_register_interval),
	samplerate(samplerate),
	new_session_callback(new_session_callback), recv_callback(recv_callback), send_callback(send_callback), end_session_callback(end_session_callback), dtmf_callback(dtmf_callback),
	global_private_data(global_private_data)
{
	if (myip.has_value())
		this->myip = myip.value();
	else {
		auto interface = find_interface_for(upstream_sip_server);

		if (!interface.has_value())
			error_exit(false, "Cannot find local IP address to reach \"%s\"", upstream_sip_server.c_str());

		this->myip = sockaddr_to_str(interface.value());

		DOLOG(debug, "Local IP address: %s\n", this->myip.c_str());
	}

	sip_fd = create_datagram_socket(myport);

	if (myport == 0) {
		if (sip_fd == -1)
			error_exit(true, "Cannot auto allocate UDP port (for SIP)");

		this->myport = get_local_addr(sip_fd).second;

		DOLOG(debug, "Local port number: %d\n", this->myport);
	}
	else if (sip_fd == 1) {
		error_exit(true, "Selected port for SIP (UDP %d) is not available", myport);
	}

	myaddr = this->myip + myformat(":%d", this->myport);

	tag    = random_hex(16);

	th1    = new std::thread(&sip::session_cleaner, this);  // session cleaner

	th2    = new std::thread(&sip::register_thread, this);  // keep-alive to upstream SIP

	th3    = new std::thread(&sip::sip_listener, this);  // listens for SIP packets
}

sip::~sip()
{
	stop_flag = true;

	close(sip_fd);

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
		int rc = poll(fds, 1, 500);

		if (rc == -1)
			break;

		if (rc == 1) {
			uint8_t     buffer[9999] { 0 };  // room for (most) jumbo frame-sizes

			sockaddr_in addr         { 0 };
			socklen_t   addr_len     { sizeof addr };

			ssize_t recv_rc = recvfrom(sip_fd, buffer, sizeof buffer - 1, 0, reinterpret_cast<struct sockaddr *>(&addr), &addr_len);

			if (recv_rc > 0) {
				std::optional<std::string> source_addr = get_host_as_text(reinterpret_cast<struct sockaddr *>(&addr));

				if (source_addr.has_value())
					DOLOG(debug, "[FROM %s] %s", source_addr.value().c_str(), buffer);
				else
					DOLOG(debug, "[FROM ?] %s", buffer);

				sip_input(&addr, sip_fd, buffer, recv_rc);
			}
		}
	}
}

void sip::sip_input(const sockaddr_in *const a, const int fd, uint8_t *const payload, const size_t payload_size)
{
	if (payload_size == 0)
		return;

	std::string              pl_str       = std::string((const char *)payload, payload_size);

	std::vector<std::string> pl_parts     = split(pl_str, "\r\n\r\n");

	std::vector<std::string> header_lines = split(pl_parts.at(0), "\r\n");

	std::vector<std::string> parts        = split(header_lines.at(0), " ");

	uint64_t now = get_us();

	if (parts.size() == 3 && parts.at(0) == "OPTIONS" && parts.at(2) == "SIP/2.0") {
		reply_to_OPTIONS(a, fd, &header_lines);
	}
	else if (parts.size() == 3 && parts.at(0) == "INVITE" && parts.at(2) == "SIP/2.0" && pl_parts.size() == 2) {
		std::vector<std::string> body_lines = split(pl_parts.at(1), "\r\n");

		reply_to_INVITE(a, fd, &header_lines, &body_lines);
	}
	else if (parts.size() == 3 && parts.at(0) == "BYE" && parts.at(2) == "SIP/2.0") {
		DOLOG(debug, "Received BYE\n");

		reply_to_BYE(a, fd, &header_lines);
	}
	else if (parts.size() >= 2 && parts.at(0) == "SIP/2.0") {
		auto str_call_id = find_header(&header_lines, "Call-ID");

		if (str_call_id.has_value() == false) {
			DOLOG(info, "Call-ID missing in headers\n");

			return;
		}

		if (str_call_id.value() == register_cid) {
			std::unique_lock<std::mutex> lck(registered_lock);

			if (parts.at(1) == "401") {
				if (now - ddos_protection > 1000000) {
					lck.unlock();

					reply_to_UNAUTHORIZED(&header_lines);

					ddos_protection = now;
				}
				else {
					DOLOG(info, "SIP: drop 401 packet\n");
				}
			}
			else if (parts.at(1) == "200") {
				is_registered = true;

				registered_cv.notify_all();
			}
		}
		else {
			if (parts.at(1) == "401")
				DOLOG(debug, "Unauthorized header received, regenerate auth-header for %s\n", str_call_id.value().c_str());

			std::unique_lock<std::mutex> lck(sessions_lock);

			for(auto & entry : sessions_pending) {
				if (entry.first == str_call_id.value()) {
					entry.second.first  = atoi(parts.at(1).c_str());

					entry.second.second = pl_parts;

					sessions_cv.notify_all();

					break;
				}
			}
		}
	}
	else {
		DOLOG(info, "SIP: request \"%s\" not understood\n", header_lines.at(0).c_str());
	}
}

static void create_response_headers(const std::string & request, std::vector<std::string> *const target, const bool upd_cseq, const std::vector<std::string> *const source, const size_t c_size, const sockaddr_in & a, const std::string & myaddr)
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

	target->push_back(myformat("Server: %s", myaddr.c_str()));

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

bool sip::transmit_packet(const sockaddr_in *const a, const int fd, const uint8_t *const data, const size_t data_size, const bool log)
{
	if (log) {
		std::optional<std::string> dest_addr = get_host_as_text(const_cast<struct sockaddr *>(reinterpret_cast<const struct sockaddr *>(a)));

		if (dest_addr.has_value())
			DOLOG(debug, "[TO %s] %s", dest_addr.value().c_str(), reinterpret_cast<const char *>(data));
		else
			DOLOG(debug, "[TO ?] %s", reinterpret_cast<const char *>(data));
	}

	return sendto(fd, data, data_size, 0, reinterpret_cast<const struct sockaddr *>(a), sizeof *a) == ssize_t(data_size);
}

std::vector<std::string> sip::generate_sdp_payload(const std::string & ip, const std::string & proto, const int rtp_port)
{
	std::vector<std::string> payload;

	payload.push_back("v=0");
	payload.push_back("o=jdoe 0 0 IN " + proto + " " + ip);
	payload.push_back("c=IN " + proto + " " + ip);
	payload.push_back("s=libHappy");
	payload.push_back("t=0 0");
	payload.push_back(myformat("m=audio %u RTP/AVP 0 8 9 11", rtp_port));
	payload.push_back("a=sendrecv");
	payload.push_back(myformat("a=rtpmap:0 PCMU/%u", samplerate));
	payload.push_back(myformat("a=rtpmap:8 PCMA/%u", samplerate));
	payload.push_back(myformat("a=rtpmap:9 G722/8000"));
	payload.push_back(myformat("a=rtpmap:11 L16/%u", samplerate));
	payload.push_back(myformat("a=rtpmap:101 telephone-event/%u", samplerate));

	return payload;
}

void sip::reply_to_OPTIONS(const sockaddr_in *const a, const int fd, const std::vector<std::string> *const headers)
{
	std::string              proto       = a->sin_family == AF_INET ? "IP4" : "IP6";

	std::vector<std::string> content     = generate_sdp_payload(sockaddr_to_str(*a), proto, 0);  // port is not allocated yet

	std::string              content_out = merge(content, "\r\n");

	std::vector<std::string> hout;
	create_response_headers("SIP/2.0 200 OK", &hout, false, headers, content_out.size(), *a, myaddr);
	std::string headers_out = merge(hout, "\r\n");

	std::string out = headers_out + "\r\n" + content_out;

	if (transmit_packet(a, fd, reinterpret_cast<const uint8_t *>(out.c_str()), out.size(), true) == false)
		DOLOG(info, "sip::reply_to_OPTIONS: transmit failed");
}

// sockaddr_in points to the RTP target
std::optional<std::pair<codec_t, struct sockaddr_in> > dissect_sdp(const std::vector<std::string> *const body, const int max_rate)
{
	codec_t                  best { 255, "", "", -1, -1 };

	int                      rtp_target_port { -1 };
	std::string              rtp_target_host;

	int                      frame_duration = 20;

	std::vector<std::string> order;

	// id, (org-)name, rate
	std::map<int, std::pair<std::string, int> > options;

	for(auto & line : *body) {
		DOLOG(debug, "SPD: %s\n", line.c_str());

		if (line.substr(0, 11) == "a=maxptime:") {
			frame_duration = std::min(40, atoi(line.substr(11).c_str()));

			DOLOG(debug, "dissect_sdp: frame duration set to %dms\n", frame_duration);

			continue;
		}

		if (line.substr(0, 2) == "o=") {
			auto parts = split(line, " ");

			rtp_target_host = parts[5];

			continue;
		}

		if (line.substr(0, 7) == "m=audio") {
			order = split(line, " ");

			rtp_target_port = atoi(order.at(1).c_str());

			// "m=audio 19206 RTP/AVP" are not of interest
			order.erase(order.begin(), order.begin() + 3);

			continue;
		}

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

		uint8_t     id   = atoi(pars.substr(0, lspace).c_str());

		std::string name = type_rate.substr(0, slash);
		int         rate = atoi(type_rate.substr(slash + 1).c_str());

		options.insert({ id, { name, rate } });
	}

	for(auto & order_element : order) {
		int  order_id    = atoi(order_element.c_str());

		auto it          = options.find(order_id);

		// might be missing due to bugs in the other end
		if (it == options.end())
			continue;

		std::string name = str_tolower(it->second.first);

		if (name == "pcma" || name == "alaw" ||
		    name == "pcmu" || name == "ulaw" ||
		    name == "l16"  ||
		    name == "g722") {
			best.id       = order_id;
			best.name     = name;
			best.org_name = it->second.first;
			best.rate     = it->second.second;

			break;
		}
	}

	if (best.id == 255) {
		DOLOG(info, "SIP: no suitable codec found\n");

		return { };
	}

	// usually 20ms
	best.frame_size     = best.rate * frame_duration / 1000;
	best.frame_duration = frame_duration;

	DOLOG(info, "SIP: CODEC chosen: %s/%d (id: %u), frame size: %d\n", best.name.c_str(), best.rate, best.id, best.frame_size);

	if (rtp_target_port == -1 || rtp_target_host.empty()) {
		DOLOG(info, "SIP: RTP target not found in SDP payload\n");

		return { };
	}

	auto          resolved_addr = resolve_name(rtp_target_host, rtp_target_port);

	if (resolved_addr.has_value() == false) {
		DOLOG(info, "SIP: cannot resolve RTP target\n");

		return { };
	}

	struct sockaddr_in rtp_target = *reinterpret_cast<struct sockaddr_in *>(&resolved_addr.value());

	return { { best, rtp_target } };
}

sip_session_t * sip::allocate_sip_session()
{
	sip_session_t *ss  = new sip_session_t();

	ss->th             = nullptr;

	ss->start_ts       = get_us();

	ss->samplerate     = samplerate;

	ss->g722_encoder   = g722_encoder_new(64000, G722_SAMPLE_RATE_8000);
	ss->g722_decoder   = g722_decoder_new(64000, G722_SAMPLE_RATE_8000);

	ss->global_private_data = global_private_data;

	// init audio resampler
	int dummy = 0;
	ss->audio_in_resample  = src_new(SRC_SINC_BEST_QUALITY, 1, &dummy);

	ss->audio_out_resample = src_new(SRC_SINC_BEST_QUALITY, 1, &dummy);

	if (!ss->audio_in_resample || !ss->audio_out_resample || !ss->g722_encoder || !ss->g722_decoder) {
		delete ss;

		return nullptr;
	}

	return ss;
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
		auto schema_addr = dissect_sdp(body, samplerate);

		if (schema_addr.has_value() == false)
			return;

		codec_t & schema = schema_addr.value().first;

		if (schema.id != 255) {
			auto call_id       = find_header(headers, "Call-ID");
			if (call_id.has_value() == false) {
				DOLOG(info, "Call-ID header missing\n");

				return;
			}

			auto from          = find_header(headers, "From");
			if (from.has_value() == false) {
				DOLOG(info, "From header missing\n");

				return;
			}

			int  rtp_fd        = create_datagram_socket(0);
			if (rtp_fd == -1) {
				DOLOG(info, "Cannot allocate RTP (UDP) port\n");

				return;
			}

			std::string from_value = from.value();

			std::size_t semi_colon = from_value.find(';');
			if (semi_colon != std::string::npos)
				from_value = from_value.substr(0, semi_colon);

			sip_session_t *ss  = allocate_sip_session();

			ss->headers        = *headers;
			memcpy(&ss->sip_addr_peer, a, sizeof ss->sip_addr_peer);
			ss->schema         = schema;
			ss->fd             = rtp_fd;
			ss->audio_port     = get_local_addr(ss->fd).second;
			ss->call_id        = call_id.value();
			ss->peer           = from_value;

			src_set_ratio(ss->audio_in_resample, double(samplerate) / schema.rate);  // TODO error checking, fail and send CANCEL

			src_set_ratio(ss->audio_out_resample, schema.rate / double(samplerate));  // TODO error checking

			content.push_back("a=sendrecv");
			content.push_back(myformat("a=rtpmap:%u %s/%u", schema.id, schema.org_name.c_str(), schema.rate));

			content.push_back(myformat("m=audio %d RTP/AVP %u", ss->audio_port, schema.id));

			std::string content_out = merge(content, "\r\n");

			if (new_session_callback(ss, from_value)) {
				// merge headers
				std::vector<std::string> hout;
				create_response_headers("SIP/2.0 200 OK", &hout, false, headers, content_out.size(), ss->sip_addr_peer, myaddr);

				std::string headers_out = merge(hout, "\r\n");

				std::string out = headers_out + "\r\n" + content_out;

				// send INVITE reply
				if (transmit_packet(a, fd, reinterpret_cast<const uint8_t *>(out.c_str()), out.size(), true) == false) {
					DOLOG(info, "sip::reply_to_INVITE: ok transmit failed");

					end_session_callback(ss);  // cannot transmit, session ended

					delete ss;
				}
				else {
					ss->th = new std::thread(&sip::session, this, schema_addr.value().second, ss);

					std::unique_lock<std::mutex> lck(sessions_lock);

					sessions.insert({ call_id.value(), ss });

					sessions_cv.notify_all();
				}
			}
			else {
				// merge headers
				std::vector<std::string> hout;
				create_response_headers("SIP/2.0 608 Rejected", &hout, false, headers, content_out.size(), ss->sip_addr_peer, myaddr);

				std::string headers_out = merge(hout, "\r\n");

				std::string out = headers_out + "\r\n" + content_out;

				// send rejection reply
				if (transmit_packet(a, fd, reinterpret_cast<const uint8_t *>(out.c_str()), out.size(), true) == false)
					DOLOG(info, "sip::reply_to_INVITE: rejection transmit failed");

				delete ss;
			}
		}
	}
}

void sip::send_ACK(const sockaddr_in *const a, const int fd, const std::vector<std::string> *const headers)
{
	std::vector<std::string> hout;
	create_response_headers("SIP/2.0 200 OK", &hout, false, headers, 0, *a, myaddr);

	std::string out = merge(hout, "\r\n");

	if (transmit_packet(a, fd, reinterpret_cast<const uint8_t *>(out.c_str()), out.size(), true) == false)
		DOLOG(info, "sip::send_ACK: transmit failed");
}

void sip::reply_to_BYE(const sockaddr_in *const a, const int fd, const std::vector<std::string> *const headers)
{
	auto call_id = find_header(headers, "Call-ID");

	if (call_id.has_value() == false) {
		DOLOG(warning, "sip::reply_to_BYE: \"Call-ID\" not found in headers\n");

		return;
	}

	{
		std::unique_lock<std::mutex> lck(sessions_lock);

		auto it = sessions.find(call_id.value());

		if (it != sessions.end()) {
			DOLOG(info, "sip::reply_to_BYE: asking thread for session \"%s\" to terminate\n", call_id.value().c_str());

			it->second->stop_flag = true;
		}
		else {
			DOLOG(warning, "sip::reply_to_BYE: session \"%s\" not found\n", call_id.value().c_str());
		}
	}

	send_ACK(a, fd, headers);
}

static std::string calculate_digest(const std::string & username, const std::string & realm, const std::string & secret, const std::string & method, const std::string & uri, const std::string & nonce)
{
	std::string a1     = md5(username + ":" + realm + ":" + secret);

	std::string a2     = md5(method + ":" + uri);

	std::string digest = md5(a1 + ":" + nonce + ":" + a2);

	return digest;
}

std::string sip::generate_authorize_header(const std::vector<std::string> *const headers, const std::string & uri, const std::string & method)
{
	auto str_wa = find_header(headers, "WWW-Authenticate");
	if (!str_wa.has_value()) {
		DOLOG(info, "SIP: \"WWW-Authenticate\" missing");
		return "";
	}

	auto        call_id = find_header(headers, "Call-ID");

	std::string work    = replace(str_wa.value(), ",", " ");

	std::vector<std::string> parameters = split(work, " ");

	std::string digest_alg = "MD5";
	auto str_da = find_header(&parameters, "algorithm", "=");
	if (str_da.has_value())
		digest_alg = str_da.value();

	std::string realm;
	auto str_realm = find_header(&parameters, "realm", "=");
	if (str_realm.has_value())
		realm = replace(str_realm.value(), "\"", "");

	std::string opaque;
	auto str_opaque = find_header(&parameters, "opaque", "=");
	if (str_opaque.has_value())
		opaque = replace(str_opaque.value(), "\"", "");

	std::string nonce;
	auto str_nonce = find_header(&parameters, "nonce", "=");
	if (str_nonce.has_value())
		nonce = replace(str_nonce.value(), "\"", "");

	std::string digest    = calculate_digest(username, realm, password, method, uri, nonce);

	std::string authorize = "Authorization: Digest username=\"" + username + "\",realm=\"" + realm + "\",nonce=\"" + nonce + "\",uri=\"" + uri + "\",algorithm=MD5,response=\"" + digest + "\"";

	if (opaque.empty() == false)
		authorize += ",opaque=\"" + opaque + "\"";

	std::string call_id_str = call_id.has_value() ? call_id.value() : "";

	{
		std::unique_lock<std::mutex> lck(registered_lock);

		register_authline = authorize;
	}

	return authorize;
}

void sip::reply_to_UNAUTHORIZED(const std::vector<std::string> *const headers)
{
	std::string auth_header = generate_authorize_header(headers, "sip:" + myaddr, "REGISTER");

	auto        call_id     = find_header(headers, "Call-ID");

	std::string call_id_str = call_id.has_value() ? call_id.value() : "";

	send_REGISTER(call_id_str, auth_header);
}

static std::pair<uint8_t *, int> create_rtp_packet(const uint32_t ssrc, const uint16_t seq_nr, const uint32_t t, const codec_t & schema, const short *const samples, const int n_samples, G722_ENC_CTX *const g722_enc)
{
	int sample_size = 0;

	if (schema.name == "alaw" || schema.name == "pcma" || schema.name == "ulaw" || schema.name == "pcmu")  // a-law and mu-law
		sample_size = sizeof(uint8_t);
	else if (schema.name == "g722")	// G722
		sample_size = sizeof(uint8_t);
	else if (schema.name == "l16")	// l16 mono
		sample_size = sizeof(uint16_t);
	else {
		DOLOG(ll_error, "SIP: Invalid rtp payload schema %s/%d\n", schema.name.c_str(), schema.rate);
		return { nullptr, 0 };
	}

	size_t size = 3 * 4 + n_samples * sample_size;
	uint8_t *rtp_packet = new uint8_t[size]();

	rtp_packet[0] |= 128;  // v2
	rtp_packet[1]  = schema.id;
	rtp_packet[2]  = seq_nr >> 8;
	rtp_packet[3]  = seq_nr;
	rtp_packet[4]  = t >> 24;
	rtp_packet[5]  = t >> 16;
	rtp_packet[6]  = t >>  8;
	rtp_packet[7]  = t;
	rtp_packet[8]  = ssrc >> 24;
	rtp_packet[9]  = ssrc >> 16;
	rtp_packet[10] = ssrc >>  8;
	rtp_packet[11] = ssrc;

	if (schema.name == "alaw" || schema.name == "pcma") {	// a-law
		for(int i=0; i<n_samples; i++)
			rtp_packet[12 + i] = encode_alaw(samples[i]);
	}
	else if (schema.name == "ulaw" || schema.name == "pcmu") {	// mu-law
		for(int i=0; i<n_samples; i++)
			rtp_packet[12 + i] = encode_mulaw(samples[i]);
	}
	else if (schema.name == "g722") {  // g.722
		g722_encode(g722_enc, samples, n_samples, &rtp_packet[12]);
	}
	else if (schema.name == "l16") {	// l16 mono
		for(int i=0; i<n_samples; i++) {
			rtp_packet[12 + i * 2 + 0] = samples[i] >> 8;
			rtp_packet[12 + i * 2 + 1] = samples[i];
		}
	}

	return { rtp_packet, size };
}

void sip::send_BYE_or_CANCEL(const sockaddr_in *const a, const std::vector<std::string> & headers, const bool is_bye)
{
	std::string extension = "0";

	auto str_to = find_header(&headers, "To");
	if (str_to.has_value()) {
		std::string::size_type lt = str_to.value().rfind('<');
		std::string::size_type gt = str_to.value().rfind('>');

		if (lt != std::string::npos && gt != std::string::npos)
			extension = str_to.value().substr(lt + 1, gt - lt - 1);
	}

	std::vector<std::string> hout;
	create_response_headers(myformat("%s %s SIP/2.0", is_bye ? "BYE " : "CANCEL", extension.c_str()), &hout, true, &headers, 0, *a, myaddr);

	std::string out = merge(hout, "\r\n") + "\r\n";

	if (transmit_packet(a, sip_fd, reinterpret_cast<const uint8_t *>(out.c_str()), out.size(), true) == false)
		DOLOG(info, "sip::send_BYE: transmit failed");
}

bool sip::transmit_audio(const sockaddr_in tgt_addr, sip_session_t *const ss, const short *const audio_in, const int n_audio_in, uint16_t *const seq_nr, uint32_t *const t, const uint32_t ssrc)
{
	int    offset    = 0;

	int    n_audio   = 0;
	short *audio     = nullptr;

	bool   resampled = false;

	if (samplerate == ss->schema.rate)
		n_audio = n_audio_in;
	else {
		resample(ss->audio_out_resample, audio_in, samplerate, n_audio_in, &audio, ss->schema.rate, &n_audio);

		resampled = true;
	}

	while(n_audio > 0 && !stop_flag && !ss->stop_flag) {
		int cur_n = std::min(n_audio, ss->schema.frame_size);

		auto rtpp = create_rtp_packet(ssrc, *seq_nr, *t, ss->schema, &(resampled ? audio : audio_in)[offset], cur_n, ss->g722_encoder);

		offset  += cur_n;
		n_audio -= cur_n;

		(*t)    += cur_n;

		(*seq_nr)++;

		if (rtpp.second) {
			if (transmit_packet(&tgt_addr, ss->fd, rtpp.first, rtpp.second, false) == false) {
				DOLOG(info, "transmit_audio: transmit failed");

				return false;
			}

			delete [] rtpp.first;
		}

		double sleep = 1000000.0 / (ss->schema.rate / double(cur_n / 8.0));
		myusleep(sleep);
	}

	if (resampled)
		delete [] audio;

	return true;
}

void sip::wait_for_audio(sip_session_t *const ss)
{
	DOLOG(info, "sip::wait_for_audio: audio receive handler thread started\n");

	// TODO: check if source address is expected

	// wait for packets on ss->fd
	// send them to audio_input()
	struct pollfd fds[] { { ss->fd, POLLIN, 0 } };

	for(;!stop_flag && !ss->stop_flag;) {
		int rc = poll(fds, 1, 500);

		if (rc == -1)
			break;

		if (rc == 1) {
			uint8_t     buffer[1600] { 0 };

			sockaddr_in addr         { 0 };
			socklen_t   addr_len     { sizeof addr };

			ssize_t recv_rc = recvfrom(ss->fd, buffer, sizeof buffer, 0, reinterpret_cast<struct sockaddr *>(&addr), &addr_len);

			if (recv_rc > 0) {
				if ((buffer[1] & 127) == 101) {
				      	// 101 is statically assigned (in this library) to "telephone-event" rtp-type
					dolog(debug, "TELEPHONE EVENT %d, %02x\n", buffer[12], buffer[13]);

					if (!dtmf_callback(buffer[12], !!(buffer[13] & 128), buffer[13] & 63, ss)) {
						ss->stop_flag = true;

						break;
					}
				}
				else {
					if (!audio_input(buffer, recv_rc, ss)) {
						ss->stop_flag = true;

						break;
					}
				}
			}
		}
	}
}

void generate_beep(const double f, const double duration, const int samplerate, short **const beep, size_t *const beep_n)
{
	*beep_n = samplerate * duration;
	*beep   = new short[*beep_n]();

	double mul = 2.0 * M_PI * f;

	for(size_t i=0; i<*beep_n; i++)
		(*beep)[i] = 32767 * sin(mul * (i + i / double(samplerate)));
}

void sip::session(const struct sockaddr_in tgt_addr, sip_session_t *const ss)
{
	set_thread_name("SIP-RTP");

	struct sockaddr_in work_addr = tgt_addr;

	DOLOG(info, "sip::session: session handler thread started. transmit to %s:%d at rate %d\n", sockaddr_to_str(work_addr).c_str(), ntohs(work_addr.sin_port), ss->schema.rate);

	std::thread audio_recv_thread([this, ss]() { wait_for_audio(ss); });

	uint16_t seq_nr = 0;
	uint32_t t      = 0;

	uint32_t ssrc   = 0;
	get_random(reinterpret_cast<uint8_t *>(&ssrc), sizeof ssrc);

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

	send_BYE_or_CANCEL(&tgt_addr, ss->headers, true);

	send_REGISTER("", "");  // required?

	audio_recv_thread.join();

	end_session_callback(ss);

	ss->finished  = true;

	DOLOG(info, "sip::session: session handler thread terminated\n");
}

// from
// http://dystopiancode.blogspot.com/2012/02/pcm-law-and-u-law-companding-algorithms.html
static int16_t decode_alaw(int8_t number)
{
	uint8_t sign     = 0x00;
	uint8_t position = 0;
	int16_t decoded  = 0;

	number ^= 0x55;

	if (number & 0x80) {
		number &= ~(1<<7);
		sign    = -1;
	}

	position = ((number & 0xF0) >>4) + 4;

	if (position != 4) {
		decoded = ((1 << position) | ((number & 0x0F) << (position - 4)) |(1 << (position - 5)));
	}
	else {
		decoded = (number << 1) | 1;
	}

	return sign == 0 ? decoded:-decoded;
}

static int16_t decode_mulaw(int8_t number)
{
	const uint16_t MULAW_BIAS = 33;
	uint8_t        sign       = 0;
	uint8_t        position   = 0;
	int16_t        decoded    = 0;

	number = ~number;

	if (number & 0x80) {
		number &= ~(1 << 7);
		sign = -1;
	}

	position = ((number & 0xF0) >> 4) + 5;

	decoded  = ((1 << position) | ((number & 0x0F) << (position - 4))
			| (1 << (position - 5))) - MULAW_BIAS;

	return sign == 0 ? decoded : -decoded;
}

bool sip::audio_input(const uint8_t *const payload, const size_t payload_size, sip_session_t *const ss)
{
	bool ok = false;

	ss->latest_pkt = get_us();

	if (ss->schema.name == "alaw" || ss->schema.name == "pcma" || ss->schema.name == "ulaw" || ss->schema.name == "pcmu") {  // a-law and mu-law
		int n_samples = payload_size - 12;

		if (n_samples > 0) {
			short *temp = new short[n_samples]();

			if (ss->schema.name == "alaw" || ss->schema.name == "pcma") {
				for(int i=0; i<n_samples; i++)
					temp[i] = decode_alaw(payload[12 + i]);
			}
			else if (ss->schema.name == "ulaw" || ss->schema.name == "pcmu") {
				for(int i=0; i<n_samples; i++)
					temp[i] = decode_mulaw(payload[12 + i]);
			}

			short *result   = nullptr;
			int    result_n = 0;
			resample(ss->audio_in_resample, temp, ss->schema.rate, n_samples, &result, samplerate, &result_n);

			if (recv_callback(result, result_n, ss))
				ok = true;

			delete [] result;

			delete [] temp;
		}
	}
	else if (ss->schema.name == "g722") { // g.722
		int n_samples = (payload_size - 12) / 2;

		if (n_samples > 0) {
			short *temp = new short[n_samples]();

			g722_decode(ss->g722_decoder, &payload[12], n_samples, temp);

			short *result   = nullptr;
			int    result_n = 0;
			resample(ss->audio_in_resample, temp, 8000, n_samples, &result, samplerate, &result_n);

			if (recv_callback(result, result_n, ss))
				ok = true;

			delete [] result;

			delete [] temp;
		}
	}
	else if (ss->schema.name == "l16") { // l16 mono
		int n_samples = (payload_size - 12) / 2;

		if (n_samples > 0) {
			const short *samples = reinterpret_cast<const short *>(&payload[12]);

			short *result   = nullptr;
			int    result_n = 0;
			resample(ss->audio_in_resample, samples, ss->schema.rate, n_samples, &result, samplerate, &result_n);

			if (recv_callback(result, result_n, ss))
				ok = true;

			delete [] result;
		}
	}
	else {
		DOLOG(warning, "SIP: unsupported incoming schema %s/%d\n", ss->schema.name.c_str(), ss->schema.rate);
	}

	if (!ok)
		DOLOG(warning, "SIP: session termination requested by recv_callback or not being able to decode rtp data\n");

	return ok;
}

void sip::session_cleaner()
{
	set_thread_name("session-cleaner");

	while(!stop_flag) {
		myusleep(500000);

		std::unique_lock<std::mutex> lck(sessions_lock);

		for(auto it=sessions.begin(); it!=sessions.end();) {
			if (it->second->finished) {
				it->second->th->join();

				delete it->second->th;
				delete it->second;

				it = sessions.erase(it);
			}
			else {
				it++;
			}
		}
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

	std::string tgt_addr = work.c_str();

	std::string out      = "REGISTER sip:" + tgt_addr + " SIP/2.0\r\n";

	std::string use_cid  = call_id;

	if (authorize.empty()) {
		out += "CSeq: 1 REGISTER\r\n";

		use_cid = random_hex(16) + "@" + myaddr;

		out += "Call-ID: " + use_cid + "\r\n";
	}
       	else {
		out += authorize + "\r\n";
		out += "CSeq: 2 REGISTER\r\n";
		out += "Call-ID: " + call_id + "\r\n";
	}

	{
		std::unique_lock<std::mutex> lck(registered_lock);

		register_cid = use_cid;
	}

	out += "Via: SIP/2.0/UDP " + myaddr + "\r\n";
	out += "User-Agent: libHappy\r\n";
	out += "From: <sip:"    + username + "@" + tgt_addr + ">;tag=" + tag + "\r\n";
	out += "To: <sip:"      + username + "@" + tgt_addr + ">\r\n";
	out += "Contact: <sip:" + username + "@" + myaddr   + ">;q=1\r\n";
	out += "Allow: INVITE,ACK,OPTIONS,BYE,CANCEL,SUBSCRIBE,NOTIFY,REFER,MESSAGE,INFO,PING\r\n";
	out += "Expires: 60\r\n";
	out += "Content-Length: 0\r\n";
	out += "Max-Forwards: 70\r\n\r\n";

	struct sockaddr_in a { 0 };
        a.sin_family      = PF_INET;
        a.sin_port        = htons(tgt_port);
        a.sin_addr.s_addr = inet_addr(tgt_addr.c_str());

	return transmit_packet(&a, sip_fd, reinterpret_cast<const uint8_t *>(out.c_str()), out.size(), true);
}

// register at upstream server
void sip::register_thread()
{
	myusleep(501000);

	while(!stop_flag) {
		int cur_interval = interval;

		if (!send_REGISTER("", ""))
			cur_interval /= 2;

		for(int i=0; i<cur_interval * 2 && !stop_flag; i++)
			myusleep(500 * 1000);
	}
}

void sip::wait_for_registered()
{
	std::unique_lock<std::mutex> lck(registered_lock);

	while(!is_registered)
		registered_cv.wait(lck);
}

void sip::forget_session(sip_session_t *const ss)
{
	std::unique_lock<std::mutex> lck(sessions_lock);

	sessions.erase(ss->call_id);

	sessions_pending.erase(ss->call_id);

	delete ss;
}

std::pair<std::optional<std::string>, int> sip::initiate_call(const std::string & target_in, const std::string & local_address, const int timeout, const bool direct)
{
	wait_for_registered();

	std::string target   = target_in;

	// use either upstream server or host of user, depending on if there's a fqdn in
	// the 'target' specification
	std::size_t at_tgt   = target.find('@');

	std::string peer_host= upstream_server;

	if (at_tgt != std::string::npos) {
		if (direct)
			peer_host = target.substr(at_tgt + 1);

		target = target.substr(0, at_tgt);
	}

	auto        a        = resolve_name(peer_host);

	if (a.has_value() == false)
		return { { }, 604 };  // could not resolve, returned as "does not exist anywhere"

	struct sockaddr_in *const addr = reinterpret_cast<struct sockaddr_in *>(&a.value());
	addr->sin_port = htons(5060);  // required later on for "create_datagram_socket_for"

	std::string call_id  = random_hex(16);

	// store session record, to be filled by sip_input()
	sip_session_t *ss  = allocate_sip_session();

	ss->call_id        = call_id;

	{
		std::unique_lock<std::mutex> lck(sessions_lock);

		sessions.insert({ call_id, ss });

		sessions_pending.insert({ call_id, { -1, { } } });
	}

	// open a port for RTP
	auto        rtp_tgt  = create_datagram_socket_for(0, *addr);

	if (rtp_tgt.has_value() == false) {
		forget_session(ss);

		return { { }, 500 };
	}

	int         rtp_fd   = rtp_tgt.value().first;

	auto        local_a  = rtp_tgt.value().second;

	// add SDP request
	std::vector<std::string> sdp_records = generate_sdp_payload(myip, "IP4", local_a.second);

	std::string sdp_data = merge(sdp_records, "\r\n");

	int         CSeq     = 1;

	std::string auth_hdr;

	std::string from_uri = "sip:" + local_address + "@" + upstream_server;

	std::size_t at_from  = local_address.find('@');

	if (at_from != std::string::npos)
		from_uri     = "sip" + local_address;

	std::string to_uri   = "sip:" + target + "@" + peer_host;

	std::string to       = "<" + to_uri + ">";

resend_INVITE_request:
	std::vector<std::string> headers_out;

	headers_out.push_back(myformat("INVITE %s SIP/2.0", to_uri.c_str()));
	headers_out.push_back("Max-Forwards: 127");
	headers_out.push_back(myformat("CSeq: %d INVITE", CSeq++));
	headers_out.push_back("To: " + to);
	headers_out.push_back("From: <" + from_uri + ">;tag=" + tag);
	headers_out.push_back("Contact: <" + from_uri + ">");
	headers_out.push_back("Call-ID: " + call_id);
	headers_out.push_back("Via: SIP/2.0/UDP " + myaddr);
	headers_out.push_back("User-Agent: libHappy");
	headers_out.push_back("Expires: 1800");

	if (auth_hdr.empty() == false)
		headers_out.push_back(auth_hdr);

	headers_out.push_back("Content-Type: application/sdp");
	headers_out.push_back(myformat("Content-Length: %zu", sdp_data.size()));

	std::string request  = merge(headers_out, "\r\n") + "\r\n" + sdp_data;

	if (transmit_packet(addr, sip_fd, reinterpret_cast<const uint8_t *>(request.c_str()), request.size(), true) == false) {
		DOLOG(info, "sip::reply_to_OPTIONS: transmit failed");

		forget_session(ss);

		return { { }, 500 };
	}

	int      wait_result = -1;
	std::vector<std::string> reply_headers;
	std::vector<std::string> reply_body;

	uint64_t wait_start  = get_ms();

	std::unique_lock<std::mutex> lck(sessions_lock);

	for(;;) {
		auto pending_it = sessions_pending.find(call_id);

		if (pending_it == sessions_pending.end()) {
			forget_session(ss);

			return { { }, 500 };  // internal error: where did the record go?!
		}

		if (pending_it->second.first >= 200) {  // -1 is "not set" and 100...199 are "wait for peer"
			wait_result   = pending_it->second.first;

			if (pending_it->second.second.size() != 2) {
				forget_session(ss);

				return { { }, 500 };  // internal error: where did the record go?!
			}

			reply_headers = split(pending_it->second.second[0], "\r\n");

			reply_body    = split(pending_it->second.second[1], "\r\n");

			if (pending_it->second.first == 401)  // requires a re-send so don't delete "pending" record
				pending_it->second.first = -1;
			else
				sessions_pending.erase(call_id);

			break;
		}

		int64_t wait_time = timeout * 1000 - (get_ms() - wait_start);

		if (wait_time <= 0) {
			forget_session(ss);

			return { { }, 504 };  // server time-out
		}

		sessions_cv.wait_for(lck, std::chrono::milliseconds(wait_time));
	}

	{
		// acknowledge e.g. a 401
		std::vector<std::string> headers_out;

		headers_out.push_back(myformat("ACK sip:%s SIP/2.0", target.c_str()));

		std::vector<std::string> copy_headers { "Via", "To", "From", "Max-Forwards", "Call-ID", "CSeq" };

		for(auto header : copy_headers) {
			auto str = find_header(&reply_headers, header);

			if (str.has_value())
				headers_out.push_back(header + ": " + str.value());
		}

		std::string request  = merge(headers_out, "\r\n");

		if (transmit_packet(addr, sip_fd, reinterpret_cast<const uint8_t *>(request.c_str()), request.size(), true) == false) {
			forget_session(ss);

			return { { }, 500 };
		}
	}

	if (wait_result == 401) {
		bool ok = true;

		do {
			auto str_to = find_header(&reply_headers, "To");

			if (str_to.has_value() == false) {
				ok = false;

				break;
			}

			auth_hdr    = generate_authorize_header(&reply_headers, to_uri, "INVITE");

			DOLOG(debug, "New auth header: %s\n", auth_hdr.c_str());

			to          = str_to.value();
		}
		while(0);

		if (!ok) {
			forget_session(ss);

			return { { }, 500 };
		}

		goto resend_INVITE_request;
	}

	auto sessions_it = sessions.find(call_id);

	if (wait_result < 200) {
		if (sessions_it != sessions.end())
			delete sessions_it->second;

		forget_session(ss);

		return { { }, 504 };  // server time-out
	}
		
	if (wait_result >= 300) {  // session did not start
		forget_session(ss);

		return { { }, wait_result };
	}

	auto schema_addr = dissect_sdp(&reply_body, samplerate);

	if (schema_addr.has_value() == false) {
		send_BYE_or_CANCEL(&ss->sip_addr_peer, ss->headers, false);

		forget_session(ss);

		return { { }, 500 };
	}

	codec_t & schema = schema_addr.value().first;

	ss->headers = reply_headers;
	memcpy(&ss->sip_addr_peer, addr, sizeof ss->sip_addr_peer);
	ss->fd             = rtp_fd;
	ss->peer           = target;
	ss->schema         = schema;
	ss->audio_port     = local_a.second;

	if (src_set_ratio(ss->audio_in_resample, double(samplerate) / schema.rate) != 0 || 
	    src_set_ratio(ss->audio_out_resample, schema.rate / double(samplerate)) != 0) {
		send_BYE_or_CANCEL(&ss->sip_addr_peer, ss->headers, false);

		forget_session(ss);

		return { { }, 500 };
	}

	// start receive thread
	ss->th = new std::thread(&sip::session, this, schema_addr.value().second, ss);

	return { call_id, wait_result };
}
