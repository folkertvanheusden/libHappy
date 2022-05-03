#include <unistd.h>

#include "sip.h"


int main(int argc, char *argv[])
{
	setlog("testhappy.log", debug, debug);

	// sip s("172.29.0.1", "9999", "1234", "172.29.0.107", 5060, 60, 44100);
	sip s("192.168.64.1", "9999", "1234", "192.168.65.158", 5060, 60, 44100);

	for(;;)
		sleep(1);

	return 0;
}
