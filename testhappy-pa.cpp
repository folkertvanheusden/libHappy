// (C) 2021 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0

// This program interfaces to pulse-audio.

#include <signal.h>
#include <unistd.h>
#include <pulse/error.h>
#include <pulse/simple.h>

#include "sip.h"


typedef struct {
	pa_simple *record;  // from pa to voip
	pa_simple *play;  // from voip to pa
} pa_sessions_t;

const pa_sample_spec ss = {
        .format   = PA_SAMPLE_S16LE,
        .rate     = 44100,
        .channels = 1
};

// invoked when a new session has started
// one can set 'session->private_data' to point to internal
// data of the callback. you need to free it yourself in
// e.g. the end_session callback.
bool cb_new_session(sip_session_t *const session)
{
	printf("cb_new_session\n");

	session->private_data = new pa_sessions_t;
	pa_sessions_t *p = reinterpret_cast<pa_sessions_t *>(session->private_data);

	int error = 0;  // TODO handle errors
	p->record = pa_simple_new(NULL, "libHappy", PA_STREAM_RECORD,   NULL, "record",   &ss, NULL, NULL, &error);

	p->play   = pa_simple_new(NULL, "libHappy", PA_STREAM_PLAYBACK, NULL, "playback", &ss, NULL, NULL, &error);

	return true;
}

// invoked when the peer produces audio and which is then
// received by us
bool cb_recv(const short *const samples, const size_t n_samples, sip_session_t *const session)
{
	pa_sessions_t *p = reinterpret_cast<pa_sessions_t *>(session->private_data);

	int error = 0;  // TODO handle errors
	pa_simple_write(p->play, samples, n_samples * sizeof(short), &error);

	return true;
}

// invoked when the library wants to send audio to
// the peer
bool cb_send(short **const samples, size_t *const n_samples, sip_session_t *const session)
{
	*n_samples = 10 * 44100 / 1000;

	*samples = new short[*n_samples];

	pa_sessions_t *p = reinterpret_cast<pa_sessions_t *>(session->private_data);

	int error = 0;  // TODO handle errors
	pa_simple_read(p->record, *samples, *n_samples * sizeof(short), &error);

	return true;
}

// called when we receive a 'BYE' from the peer (and
// the session thus ends)
void cb_end_session(sip_session_t *const session)
{
	printf("cb_end_session\n");

	pa_sessions_t *p = reinterpret_cast<pa_sessions_t *>(session->private_data);

	pa_simple_free(p->play);

	pa_simple_free(p->record);

	delete p;
}

void sigh(int sig)
{
}

int main(int argc, char *argv[])
{
	signal(SIGINT, sigh);

	// filename, loglevel for logging to file, level for logging to screen
	// levels: debug, info, warning, ll_error
	setlog("testhappy.log", debug, debug);

	// remote ip (IP address of upstream asterisk server), my extension-number, my password, my ip, my sip port, samplerate-used-by-callbacks, [callbacks...]
	sip s("192.168.64.1", "9999", "1234", "192.168.65.201", 5060, 60, 44100, cb_new_session, cb_recv, cb_send, cb_end_session);

	// do whatever you like here
	pause();

	return 0;
}
