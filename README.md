See testhappy.cpp for an explanation how to use the library in your own program.


required packages:
* libsamplerate0-dev
* libsndfile1-dev
* libspeex-dev
* libssl-dev

for the alsa test program:
* libasound2-dev

You need 'cmake' (and 'build-essentials' on debian/ubuntu) to build the library/test programs.

cmake install

... will install the library and a .pc-file (for pkg-config).


This library has been tested with the Asterisk VOIP server application.


written by Folkert van Heusden

released under apache license v2
