what it is
----------

This program allows you to interface to a VOIP/SIP server.

When connected, you will receive audio and dtmf from incoming calls (only) via callbacks.

Via these callbacks you will be notified of new sessions, you will receive audio and can send audio and you will be informed about DTMF key presses.


compiling the library
---------------------

required packages:
* libsamplerate0-dev
* libsndfile1-dev

for the alsa test program:
* libasound2-dev

You need 'cmake' (and 'build-essentials' on debian/ubuntu) to build the library/test programs.

cmake install

... will install the library and a .pc-file (for pkg-config).


demo
----

Call +31317794512. Then in the main menu press '2' and in the second menu press '7'. You will/should hear music playing and if so, you can talk which will be heard by the people playing the music.


usage
-----
See testhappy[-alsa].cpp for examples how to use the library in your own program.

Using the library should be not too difficult.

You instantiate the 'sip' class with the following parameters

* upstream SIP server: IP address of the SIP server you want to talk to (this server should route calls to the extension for which the library will register)

* upstream SIP server user: username of the SIP account you want to use
* upstream SIP server password: password of the SIP account you want to use

* local IP address: this is only required if there is a NAT router between libhappy and the target sip-server or when the local IP address cannot automatically be determined

* local port: UDP port on which the library will listen for incoming SIP packets 

* register interval: how often to login/notify the SIP server that we're ready to use the service

* sample rate: sample rate of the audio send to/expected from the callbacks. E.g. 44100.

The last 5 parameters are pointers to the callback functions:

* bool new\_session(session\_t \*const session)
  Called when a new SIP session is starting. Return true if you're ready, false to deny.

* bool recv\_callback(const short \*const samples, const size\_t n\_samples, sip\_session\_t \*const session)
  Called when the library received audio from "the other end" (the peer). Return false if you want to abort the session.

* bool send\_callback(short \*\*const samples, size\_t \*const n\_samples, sip\_session\_t \*const session)
  Called when the library should transmit audio to the peer. Return false if you want to abort the session.

* void end\_session(sip\_session\_t \*const session)
  Called when the session is terminated by the other end.

* void dtmf(const uint8\_t dtmf\_code, const bool is\_end, const uint8\_t volume, sip\_session\_t \*const session)
  Called when a DTMF code is received. This can come in multiple times, depending on how long someone keeps the button on the phone pressed.


The sip\_session\_t structure contains a few parameters relevant to the session.
The only ones you should use are:

* call\_id - this should be a unique identifier for a session.

* private\_data - this pointer can be used to store private session data. You should free it yourself in e.g. the end\_session callback.

* schema.frame\_duration - this integer tells you how long (in milliseconds) a packet of data should be (maximum) when send\_callback is invoked.


This library has been tested with the Asterisk VOIP server application (SIP and the new PJSIP drivers).
You may need to tell your VOIP server to use either ALAW, PCMA or L16.


written by Folkert van Heusden <mail@vanheusden.com> in 2022

released under apache license v2

<a href="https://scan.coverity.com/projects/folkertvanheusden-libhappy"><img alt="Coverity Scan Build Status" src="https://scan.coverity.com/projects/25018/badge.svg"/></a>

[![Language grade: C/C++](https://img.shields.io/lgtm/grade/cpp/g/folkertvanheusden/libHappy.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/folkertvanheusden/libHappy/context:cpp)
