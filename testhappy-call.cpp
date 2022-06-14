// (C) 2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <signal.h>
#include <unistd.h>

#include "sip.h"


// invoked when a new session has started
// one can set 'session->private_data' to point to internal
// data of the callback. you need to free it yourself in
// e.g. the end_session callback.
bool cb_new_session(sip_session_t *const session, const std::string & from)
{
	printf("cb_new_session, call-id: %s, caller: %s\n", session->call_id.c_str(), from.c_str());

	return true;
}

// invoked when the peer produces audio and which is then
// received by us
bool cb_recv(const short *const samples, const size_t n_samples, sip_session_t *const session)
{
	printf("cb_recv: %zu samples\n", n_samples);

	FILE *fh = fopen("test.pcm", "a+");
	if (fh) {
		fwrite(samples, sizeof(short), n_samples, fh);

		fclose(fh);
	}

	return true;
}

// invoked when the library wants to send audio to
// the peer
bool cb_send(short **const samples, size_t *const n_samples, sip_session_t *const session)
{
//	printf("cb_send\n");

	generate_beep(800, 0.04, session->samplerate, samples, n_samples);

	return true;
}

// called when we receive a 'BYE' from the peer (and
// the session thus ends)
void cb_end_session(sip_session_t *const session)
{
}

// invoked when a DTMF signal has been received
// note that may come in multiple times for the
// same key-press. this is due to how they are
// transmitted
bool cb_dtmf(const uint8_t dtmf_code, const bool is_end, const uint8_t volume, sip_session_t *const session)
{
	printf("DTMF pressed: %d\n", dtmf_code);

	return true;
}

void sigh(int sig)
{
}

int main(int argc, char *argv[])
{
//	signal(SIGINT, sigh);

	// filename, loglevel for logging to file, level for logging to screen
	// levels: debug, info, warning, ll_error
	setlog("testhappy.log", debug, debug);

	// remote ip (IP address of upstream asterisk server), my extension-number, my password, my ip, my sip port, samplerate-used-by-callbacks, [callbacks...], pointer to global private data (or nullptr)
	// note: 'my ip' is only required when the library cannot figure out what IP address to use to contact the SIP server. This can happen when there's a NAT router in between for example.
//sip s("172.29.0.113", "9999", "1234", { }, 0, 60, 44100, cb_new_session, cb_recv, cb_send, cb_end_session, cb_dtmf, nullptr);

	// sip s("10.208.11.13", "3535", "1234", { }, 0, 60, 44100, cb_new_session, cb_recv, cb_send, cb_end_session, cb_dtmf, nullptr);

	// sip s("172.29.0.93", "9997", "1234", { }, 0, 60, 44100, cb_new_session, cb_recv, cb_send, cb_end_session, cb_dtmf, nullptr);

	// sip s("192.168.122.115", "9999", "1234", { }, 0, 60, 44100, cb_new_session, cb_recv, cb_send, cb_end_session, cb_dtmf, nullptr);

sip s("192.168.64.13", "9999", "1234", { }, 0, 60, 44100, cb_new_session, cb_recv, cb_send, cb_end_session, cb_dtmf, nullptr);

///	auto rc = s.initiate_call("22222@172.29.0.11", "9999@172.29.0.107", 15, true);

	// auto rc = s.initiate_call("4455", "3535", 15, false);

	// auto rc = s.initiate_call("1000", "9997", 15, false);
	// auto rc = s.initiate_call("22222@172.29.0.93", "9997", 15, true);

	// auto rc = s.initiate_call("22222@192.168.64.13", "9999", 15, false);

	//auto rc = s.initiate_call("1212@192.168.64.13", "4107", 15, false);

	auto rc = s.initiate_call("8463@jhcloos.com", "9999", 15, call_direct);

	printf("%d\n", rc.second);

	getchar();

	return 0;
}
