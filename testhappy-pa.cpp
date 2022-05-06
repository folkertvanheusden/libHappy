// (C) 2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0

// This program interfaces to pulse-audio.

#include <condition_variable>
#include <cstring>
#include <queue>
#include <signal.h>
#include <unistd.h>
#include <pulse/error.h>
#include <pulse/simple.h>

#include "sip.h"


typedef struct {
	std::thread *rec_th;  // recorder thread

	std::mutex   buffer_lock;
	std::condition_variable_any buffer_cv;
	int          buffer_length;
	std::queue<short *> buffers;

	pa_simple   *record;  // from pa to voip
	pa_simple   *play;  // from voip to pa

	std::atomic_bool *stop_flag;
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

	int fragment_size   = 20;  // in ms

	p->buffer_length    = session->samplerate * fragment_size / 1000;

	p->stop_flag        = &session->stop_flag;

	p->rec_th = new std::thread([p, fragment_size]() {
			double t_avg = 0;

			double  gain_n_samples = 150.0 / fragment_size;  // calculate fragment over 150ms

			while(!*p->stop_flag) {
				short *buffer = new short[p->buffer_length];

				int error = 0;  // TODO handle errors
				pa_simple_read(p->record, buffer, p->buffer_length * sizeof(short), &error);

				// update moving average for gain
				double avg = 0;

				for(int i=0; i<p->buffer_length; i++)
					avg += buffer[i];

				avg /= p->buffer_length;

				t_avg = (t_avg * gain_n_samples + avg) / (gain_n_samples + 1);

				// apply
				double gain = std::min(5.0, 32767 / std::max(1.0, t_avg));

				for(int i=0; i<p->buffer_length; i++)
					buffer[i] *= gain;

				std::unique_lock<std::mutex> lck(p->buffer_lock);
				p->buffers.push(buffer);

				p->buffer_cv.notify_all();
			}
		});

	// some time to let the recording thread fill the queue
	myusleep(101000);

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
	pa_sessions_t *p = reinterpret_cast<pa_sessions_t *>(session->private_data);

	std::unique_lock<std::mutex> lck(p->buffer_lock);

	using namespace std::chrono_literals;

	while(p->buffers.empty()) {
		p->buffer_cv.wait_for(lck, 500ms);

		if (*p->stop_flag) {
			printf("cb_send: terminate by stop_flag\n");

			return false;
		}
	}

	*samples   = p->buffers.front();
	p->buffers.pop();

	*n_samples = p->buffer_length;

	return true;
}

// called when we receive a 'BYE' from the peer (and
// the session thus ends)
void cb_end_session(sip_session_t *const session)
{
	printf("cb_end_session\n");

	pa_sessions_t *p   = reinterpret_cast<pa_sessions_t *>(session->private_data);

	session->stop_flag = true;

	p->rec_th->join();
	delete p->rec_th;

	while(p->buffers.empty() == false) {
		delete [] p->buffers.front();

		p->buffers.pop();
	}

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
	// sip s("192.168.64.1", "9999", "1234", "192.168.65.158", 5060, 60, 44100, cb_new_session, cb_recv, cb_send, cb_end_session);
	sip s("10.208.11.13", "3131", "1234", "10.208.42.59", 5060, 60, 44100, cb_new_session, cb_recv, cb_send, cb_end_session);

	// do whatever you like here
	pause();

	return 0;
}
