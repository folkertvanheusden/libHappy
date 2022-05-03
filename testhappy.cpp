#include <mutex>
#include <string.h>
#include <unistd.h>

#include "sip.h"


std::mutex lock;
short buffer[4096];
size_t n = 0;

bool cb_new_session(sip_session_t *const session)
{
	return true;
}

bool cb_recv(const short *const samples, const size_t n_samples, sip_session_t *const session)
{
	std::unique_lock lck(lock);

	memcpy(buffer, samples, n_samples * 2);

	n = n_samples;

	return true;
}

bool cb_send(short **const samples, size_t *const n_samples, sip_session_t *const session)
{
	std::unique_lock lck(lock);

	*samples = new short[n];
	memcpy(*samples, buffer, n * 2);

	*n_samples = n;

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
