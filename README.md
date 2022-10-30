A very simple pcap example. It returns the length of the packet if there is a captured one.
To build and run, use gcc with lpcap on a Linux machine;
$ gcc -o pcap pcap.o -lpcap 