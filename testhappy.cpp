#include <unistd.h>

#include "sip.h"


bool cb_new_session(sip_session_t *const session)
{
	return true;
}

bool cb_recv(const short *const samples, const size_t n_samples, sip_session_t *const session)
{
	printf("%zu\n", n_samples);
	FILE *fh = fopen("test.smp", "a+");
	if (fh) {
		fwrite(samples, sizeof(short), n_samples, fh);

		fclose(fh);
	}

	return true;
}

bool cb_send(short **const samples, size_t *const n_samples, sip_session_t *const session)
{
	generate_beep(440, 0.1, 44100, samples, n_samples);

	return true;
}

void cb_end_session(sip_session_t *const session)
{
}

int main(int argc, char *argv[])
{
	setlog("testhappy.log", debug, debug);

	// remote ip, my number, my password, my pip, my sip port, samplerate-used-by-callbacks, [callbacks...]
	sip s("172.29.0.1", "9999", "1234", "172.29.0.107", 5060, 60, 44100, cb_new_session, cb_recv, cb_send, cb_end_session);

	for(;;)
		sleep(1);

	return 0;
}
