// (C) 2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0

// This program interfaces to pulse-audio.

#include <condition_variable>
#include <cstring>
#include <queue>
#include <signal.h>
#include <unistd.h>
#include <alsa/asoundlib.h>

#include "sip.h"


typedef struct {
	std::thread *rec_th;  // recorder thread

	std::mutex   buffer_lock;
	std::condition_variable_any buffer_cv;
	int          buffer_length;
	std::queue<short *> buffers;

	snd_pcm_t   *capture_handle; // from alsa to voip

	double t_avg = 0;

	snd_pcm_t   *play_handle;  // from voip to alsa

	std::atomic_bool *stop_flag;
} alsa_sessions_t;

snd_pcm_t *open_alsa_record(const std::string & dev_name, int *const frames)
{
	snd_pcm_t *capture_handle { nullptr };

	int err = snd_pcm_open(&capture_handle, dev_name.c_str(), SND_PCM_STREAM_CAPTURE, 0);

	if (err < 0) {
		fprintf(stderr, "cannot open audio device %s (%s)\n", dev_name.c_str(), snd_strerror(err));

		return nullptr;
	}

	snd_pcm_hw_params_t *hw_params { nullptr };

	err = snd_pcm_hw_params_malloc(&hw_params);

	if (err < 0) {
		fprintf(stderr, "cannot allocate hardware parameter structure (%s)\n", snd_strerror(err));

		return nullptr;
	}

	err = snd_pcm_hw_params_any(capture_handle, hw_params);

	if (err < 0) {
		fprintf(stderr, "cannot initialize hardware parameter structure (%s)\n", snd_strerror(err));

		return nullptr;
	}

	err = snd_pcm_hw_params_set_format(capture_handle, hw_params, SND_PCM_FORMAT_S16_LE);

	if (err < 0) {
		fprintf(stderr, "cannot set sample format (%s)\n", snd_strerror(err));

		return nullptr;
	}

	unsigned rate = 44100;
	err = snd_pcm_hw_params_set_rate_near(capture_handle, hw_params, &rate, 0);

	if (err < 0) {
		fprintf(stderr, "cannot set sample rate (%s)\n", snd_strerror(err));

		return nullptr;
	}

	if (rate != 44100) {
		fprintf(stderr, "audio device cannot handle 44100Hz\n");

		return nullptr;
	}

	err = snd_pcm_hw_params_set_channels(capture_handle, hw_params, 1);

	if (err < 0) {
		fprintf(stderr, "cannot set channel count (%s)\n", snd_strerror(err));
		
		return nullptr;
	}

	long unsigned temp_frames = *frames;
	int dir { 0 };
	snd_pcm_hw_params_set_period_size_near(capture_handle, hw_params, &temp_frames, &dir);
	*frames = temp_frames;

	printf("%d %d\n", *frames, dir);

	err = snd_pcm_hw_params(capture_handle, hw_params);

	if (err < 0) {
		fprintf(stderr, "cannot set parameters (%s)\n", snd_strerror(err));

		return nullptr;
	}

	snd_pcm_hw_params_free(hw_params);

	err = snd_pcm_prepare(capture_handle);

	if (err < 0) {
		fprintf(stderr, "cannot prepare audio interface for use (%s)\n", snd_strerror(err));

		return nullptr;
	}

	return capture_handle;
}

snd_pcm_t *open_alsa_play(const std::string & dev_name)
{
	snd_pcm_t           *play_handle { nullptr };

	snd_pcm_hw_params_t *params { nullptr };

	/* Open the PCM device in playback mode */
	int err = snd_pcm_open(&play_handle, dev_name.c_str(), SND_PCM_STREAM_PLAYBACK, 0);

	if (err < 0) {
		printf("ERROR: Can't open \"%s\" PCM device %s\n", dev_name.c_str(), snd_strerror(err));

		return nullptr;
	}

	snd_pcm_hw_params_alloca(&params);

	snd_pcm_hw_params_any(play_handle, params);

	err = snd_pcm_hw_params_set_format(play_handle, params, SND_PCM_FORMAT_S16_LE);

	if (err < 0)
		printf("ERROR: Can't set format %s\n", snd_strerror(err));

	snd_pcm_hw_params_set_channels(play_handle, params, 1);

	unsigned rate = 44100;
	err = snd_pcm_hw_params_set_rate_near(play_handle, params, &rate, 0);

	if (err < 0)
		printf("ERROR: Can't set rate %s\n", snd_strerror(err));

	snd_pcm_hw_params(play_handle, params);

	return play_handle;
}

// invoked when a new session has started
// one can set 'session->private_data' to point to internal
// data of the callback. you need to free it yourself in
// e.g. the end_session callback.
bool cb_new_session(sip_session_t *const session)
{
	printf("cb_new_session, call-id: %s\n", session->call_id.c_str());

	session->private_data = new alsa_sessions_t;
	alsa_sessions_t   *p = reinterpret_cast<alsa_sessions_t *>(session->private_data);

	p->buffer_length   = 44100 * session->schema.frame_duration / 1000;

	printf("buffer length: %d, frame size: %d, frame duration %d\n", p->buffer_length, session->schema.frame_size, session->schema.frame_duration);

	// TODO handle errors
	p->capture_handle   = open_alsa_record("default", &p->buffer_length);

	if (!p->capture_handle)
		return false;

	p->play_handle      = open_alsa_play("default");

	if (!p->play_handle)
		return false;

	p->stop_flag        = &session->stop_flag;

	p->rec_th           = nullptr;

	return true;
}

// invoked when the peer produces audio and which is then
// received by us
bool cb_recv(const short *const samples, const size_t n_samples, sip_session_t *const session)
{
	alsa_sessions_t *p = reinterpret_cast<alsa_sessions_t *>(session->private_data);

	double  gain_n_samples = 300.0 / session->schema.frame_duration; // calculate fragment over 300ms

	printf("duration: %d, blen: %d\n", session->schema.frame_duration, p->buffer_length);

	// update moving average for gain
	double avg = 0;

	for(int i=0; i<n_samples; i++)
		avg += samples[i];

	avg /= p->buffer_length;

	p->t_avg = (p->t_avg * gain_n_samples + avg) / (gain_n_samples + 1);

	// apply
	double gain = std::max(1.5, std::min(5.0, 32767 / std::max(1.0, p->t_avg)));

	// TODO clamp to -1...1
	for(int i=0; i<n_samples; i++)
		((short *)samples)[i] *= gain;

	int err = snd_pcm_writei(p->play_handle, samples, n_samples);

	if (err == -EPIPE) {
		printf("EPIPE\n");

		snd_pcm_prepare(p->play_handle);
	}
	else if (err < 0) {
		printf("ERROR Can't write to PCM device %s\n", snd_strerror(err));

		return false;
	}

	return true;
}

// invoked when the library wants to send audio to
// the peer
bool cb_send(short **const samples, size_t *const n_samples, sip_session_t *const session)
{
	alsa_sessions_t *p = reinterpret_cast<alsa_sessions_t *>(session->private_data);

	if (p->rec_th == nullptr) {
		p->rec_th = new std::thread([p, session]() {
			while(!*p->stop_flag) {
				uint64_t start = get_us();

				short *buffer = new short[p->buffer_length];

				int err = snd_pcm_readi(p->capture_handle, buffer, p->buffer_length);
				if (err < 0)
					fprintf(stderr, "read %d frames from audio interface failed (%s)\n", p->buffer_length, snd_strerror(err));

				std::unique_lock<std::mutex> lck(p->buffer_lock);

				p->buffers.push(buffer);

				p->buffer_cv.notify_all();

				uint64_t fin = get_us();

				printf("record audio: %lu\n", fin - start);
			}
		});
	}

	std::unique_lock<std::mutex> lck(p->buffer_lock);

	using namespace std::chrono_literals;

	uint64_t start = get_us();

	while(p->buffers.empty()) {
		p->buffer_cv.wait_for(lck, 500ms);

		if (*p->stop_flag) {
			printf("cb_send: terminate by stop_flag\n");

			return false;
		}
	}

	uint64_t fin = get_us();

	printf("wait for audio: %lu\n", fin - start);

	*samples   = p->buffers.front();
	p->buffers.pop();

	*n_samples = p->buffer_length;

	return true;
}

// called when we receive a 'BYE' from the peer (and
// the session thus ends)
void cb_end_session(sip_session_t *const session)
{
	printf("cb_end_session, call-id: %s\n", session->call_id.c_str());

	alsa_sessions_t *p   = reinterpret_cast<alsa_sessions_t *>(session->private_data);

	session->stop_flag = true;

	p->rec_th->join();
	delete p->rec_th;

	while(p->buffers.empty() == false) {
		delete [] p->buffers.front();

		p->buffers.pop();
	}

	snd_pcm_close(p->play_handle);

	snd_pcm_close(p->capture_handle);

	delete p;
}

void cb_dtmf(const uint8_t dtmf_code, const bool is_end, const uint8_t volume, sip_session_t *const session)
{
	printf("DTMF pressed: %d\n", dtmf_code);
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
	//sip s("192.168.64.1", "9999", "1234", "192.168.65.158", 5060, 60, 44100, cb_new_session, cb_recv, cb_send, cb_end_session, cb_dtmf);
	sip s("10.208.11.13", "3535", "1234", "10.208.42.97", 5060, 60, 44100, cb_new_session, cb_recv, cb_send, cb_end_session, cb_dtmf);

	// do whatever you like here
	pause();

	return 0;
}
