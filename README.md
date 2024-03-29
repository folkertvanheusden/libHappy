what it is
----------

This program allows you to interface to a VOIP/SIP server.

When connected, you will receive audio and dtmf from incoming calls (only) via callbacks.

Via these callbacks you will be notified of new sessions, you will receive audio and can send audio and you will be informed about DTMF key presses.


compiling the library
---------------------

required packages:
* libsamplerate0-dev

for the alsa test program:
* libasound2-dev

You need 'cmake' (and 'build-essentials' on debian/ubuntu) to build the library/test programs.

cmake install

... will install the library and a .pc-file (for pkg-config).

Note that if the libg722 directory is empty, then invoke first (before running make):
* cd libg722
* git submodule init
* git submodule update
* cd ..


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

* local IP address: this is only required if there is a NAT router between libhappy and the target sip-server or when the local IP address cannot automatically be determined, else use { }

* local port: UDP port on which the library will listen for incoming SIP packets. normally you would set this to 0 for automatically choose one.

* register interval: how often to login/notify the SIP server that we're ready to use the service

* sample rate: sample rate of the audio send to/expected from the callbacks. E.g. 44100.

The last 5 parameters are pointers to the callback functions:

* bool new\_session(session\_t \*const session, const std::string & from)
  Called when a new SIP session is starting. Return true if you're ready, false to deny.
  session-\>headers contains all the INVITE request-headers.
  'from' is a copy of the SIP "From"-field. It contains the address of the caller.

* bool recv\_callback(const short \*const samples, const size\_t n\_samples, sip\_session\_t \*const session)
  Called when the library received audio from "the other end" (the peer). Return false if you want to abort the session.

* bool send\_callback(short \*\*const samples, size\_t \*const n\_samples, sip\_session\_t \*const session)
  Called when the library should transmit audio to the peer. Return false if you want to abort the session.

* void end\_session(sip\_session\_t \*const session)
  Called when the session is terminated by the other end.

* void dtmf(const uint8\_t dtmf\_code, const bool is\_end, const uint8\_t volume, sip\_session\_t \*const session)
  Called when a DTMF code is received. This can come in multiple times, depending on how long someone keeps the button on the phone pressed.


When the sip-class is instantiated with the parameters above then you can receive calls.

When you invoke:

    auto rc = initiate_call(const std::string & target, const std::string & local_address, const int timeout);

e.g.:

    auto rc = initiate_call("22222@vps001.vanheusden.com", "9997", 15, true);

...then libHappy will make a call to 22222@vps001.vanheusden.com with "9997@upstream-sip-server" as your local endpoint.
15 is the number of seconds it will wait for the other end to respond.

If 'direct' is true then the library will connect directly to the peer, not via the 'upstream\_sip\_server.


The sip\_session\_t structure contains a few parameters relevant to the session.
The only ones you should use are:

* call\_id - this should be a unique identifier for a session.

* private\_data - this pointer can be used to store private session data. You should free it yourself in e.g. the end\_session callback.

* schema.frame\_duration - this integer tells you how long (in milliseconds) a packet of data should be (maximum) when send\_callback is invoked.


This library has been tested with the Asterisk VOIP server application (SIP and the new PJSIP drivers).
You may need to tell your VOIP server to use either ALAW, PCMA, ULAW, PCMU, G.722 or L16.
When using PJSIP in Asterisk, set "auth\_type = md5" for the libhappy endpoint.


written by Folkert van Heusden <mail@vanheusden.com> in 2022-2023

CC0 license
