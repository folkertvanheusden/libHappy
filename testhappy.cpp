#include <unistd.h>

#include "sip.h"


constexpr int sample_rate = 44100;

bool cb_new_session(sip_session_t *const session)
{
	return true;
}

bool cb_recv(const short *const samples, const size_t n_samples, sip_session_t *const session)
{
	FILE *fh = fopen("test.pcm", "a+");
	if (fh) {
		fwrite(samples, sizeof(short), n_samples, fh);

		fclose(fh);
	}

	return true;
}

bool cb_send(short **const samples, size_t *const n_samples, sip_session_t *const session)
{
	generate_beep(440, 0.1, sample_rate, samples, n_samples);

	return true;
}

void cb_end_session(sip_session_t *const session)
{
}

int main(int argc, char *argv[])
{
	setlog("testhappy.log", debug, debug);

	// remote ip, my number, my password, my pip, my sip port, samplerate-used-by-callbacks, [callbacks...]
	// sip s("172.29.0.1", "9999", "1234", "172.29.0.107", 5060, 60, sample_rate, cb_new_session, cb_recv, cb_send, cb_end_session);
	sip s("192.168.64.1", "9999", "1234", "192.168.65.201", 5060, 60, sample_rate, cb_new_session, cb_recv, cb_send, cb_end_session);

	for(;;)
		sleep(1);

	return 0;
}
