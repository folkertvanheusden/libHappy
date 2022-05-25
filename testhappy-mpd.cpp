// (C) 2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0

#include <signal.h>
#include <libmpd/libmpd.h>

#include "sip.h"


typedef struct {
	// last (DTMF) key pressed (or 255)
	uint8_t           prev_key;
} mpd_sessions_t;

// invoked when a new session has started
// one can set 'session->private_data' to point to internal
// data of the callback. you need to free it yourself in
// e.g. the end_session callback.
bool cb_new_session(sip_session_t *const session, const std::string & from)
{
	printf("cb_new_session, call-id: %s, caller: %s\n", session->call_id.c_str(), from.c_str());

	session->private_data = new mpd_sessions_t;
	mpd_sessions_t   *p   = reinterpret_cast<mpd_sessions_t *>(session->private_data);

	p->prev_key           = 255;

	return true;
}

// no audio, just dtmf

// invoked when the peer produces audio and which is then
// received by us
bool cb_recv(const short *const samples, const size_t n_samples, sip_session_t *const session)
{
	return true;
}

// invoked when the library wants to send audio to
// the peer
bool cb_send(short **const samples, size_t *const n_samples, sip_session_t *const session)
{
	return true;
}

// called when we receive a 'BYE' from the peer (and
// the session thus ends)
void cb_end_session(sip_session_t *const session)
{
	printf("cb_end_session, call-id: %s\n", session->call_id.c_str());

	mpd_sessions_t *p = reinterpret_cast<mpd_sessions_t *>(session->private_data);

	delete p;
}

void cb_dtmf(const uint8_t dtmf_code, const bool is_end, const uint8_t volume, sip_session_t *const session)
{
	printf("DTMF pressed: %d\n", dtmf_code);

	mpd_sessions_t *p   = reinterpret_cast<mpd_sessions_t *>(session->private_data);

	MpdObj         *mpd = reinterpret_cast<MpdObj *>(session->global_private_data);

	if (is_end && dtmf_code != p->prev_key) {

		if (dtmf_code == 4) {  // previous
			mpd_player_prev(mpd);
		}
		else if (dtmf_code == 5) {  // pause / unpause
			int state = mpd_player_get_state(mpd);

			if (state == MPD_STATUS_STATE_PAUSE || state == MPD_STATUS_STATE_STOP)
				mpd_player_play(mpd);
			else if (state == MPD_STATUS_STATE_PLAY)
				mpd_player_pause(mpd);
			else
				printf("Unknown MPD state: %d\n", state);
		}
		else if (dtmf_code == 6) {  // next
			mpd_player_next(mpd);
		}
		else {
			printf("Ignoring DTMF code %d\n", dtmf_code);
		}

		p->prev_key = dtmf_code;
	}
}

void sigh(int sig)
{
}

int main(int argc, char *argv[])
{
	signal(SIGINT, sigh);

	setlog("/tmp/testhappy.log", debug, debug);

	MpdObj *mpd = mpd_new(const_cast<char *>("spacesound.vm.nurd.space"), 6600, nullptr);

	sip s("10.208.11.13", "3737", "1234", { }, 5061, 60, 44100, cb_new_session, cb_recv, cb_send, cb_end_session, cb_dtmf, mpd);

	pause();

	return 0;
}
