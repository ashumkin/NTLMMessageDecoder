NTLMMessageDecoder
==================

NTLM Message Decoder

>I've just finished hacking up a very small program I should have written years ago. It turns out the ability to reverse engineer an NTLM HTTP proxy authentication message is still useful, and thus, NTLMMessageDecoder is here.

>All it does is automate the deconstruction of the three NTLM message types as described here and elsewhere. It takes the base64 encoded version of the NTLM message (as it appears in the HTTP header) on standard input and spits out the results on standard output.

>The source code is included (under the Creative Commons license), as well as a pre-built version for Intel Macs. To build your own version, just run make. Note that big endian architectures will need to edit the ltohl and ltohs functions (in main.c) to swap the endianess. Since I also built this on my Powerbook, here's an example of functions that will do the job:

``short ltohs(short in) { return ((in&0xFF) << 8) | ((in&0xFF00) >> 8); }``
``long ltohl(long in) { return ((in&0xFF) << 24) | ((in&0xFF00) << 8) |
                             ((in&0xFF0000) >> 8) | ((in&0xFF000000) >> 24); }``
>I welcome modification submissions (detecting endianess, better formatting, NTLM improvements, etc.) and will publish your work, with attributions, under the same license if you like.

>Posted by LightYear on August 12, 2008 10:51 AM | [Permalink] [1]

[1]: http://heath.hrsoftworks.net/archives/000217.html
