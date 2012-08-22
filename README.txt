This set contains some tools to process network trace.

=====
Tools from OMNILAB, SJTU. http://omnilab.sjtu.edu.cn/
"tracecap":
	A light trace dumper with time setter and filters. Very simpler than Tcpdump. Find more usage information from its README file.

"FeatureGen"
	Generate various features of tcp flows. By Li Zhang
	
"replay"
	TCP flow replayer. By Yingdi Yu

=====
Tools developed by other programmers or organizations:

"tcpdump/libpcap":
	This is the official site of tcpdump, a powerful command-line packet analyzer; and libpcap, a portable C/C++ library for network traffic capture.
	http://www.tcpdump.org/

"tcpsplit":
	The tcpsplit utility breaks a single libpcap packet trace into some number of sub-traces, breaking the trace along TCP connection boundaries so that a TCP connection doesn't end up split across two sub-traces. This is useful for making large trace files tractable for in-depth analysis and for subsetting a trace for developing analysis on only part of a trace.
	http://www.icir.org/mallman/software/tcpsplit/

"tcpflow":
	tcpflow is a program that captures data transmitted as part of TCP connections (flows), and stores the data in a way that is convenient for protocol analysis or debugging. A program like 'tcpdump' shows a summary of packets seen on the wire, but usually doesn't store the data that's actually being transmitted. In contrast, tcpflow reconstructs the actual data streams and stores each flow in a separate file for later analysis.
	http://www.circlemud.org/jelson/software/tcpflow/

"tcptrace":
	tcptrace is a tool written by Shawn Ostermann at Ohio University, for analysis of TCP dump files. It can take as input the files produced by several popular packet-capture programs, including tcpdump, snoop, etherpeek, HP Net Metrix, and WinDump. tcptrace can produce several different types of output containing information on each connection seen, such as elapsed time, bytes and segments sent and recieved, retransmissions, round trip times, window advertisements, throughput, and more. It can also produce a number of graphs for further analysis.
	http://tcptrace.org/index.html
	
"pcap2har":
	converts .pcap network capture files to HTTP Archive files.
	https://github.com/andrewf/pcap2har
	
"dpkt":
	fast, simple packet creation / parsing, with definitions for the basic TCP/IP protocols.
	http://code.google.com/p/dpkt/

"wireshark":
	All tools in wireshark package:
	capinfos - Prints information about capture files
	dftest - Shows display filter byte-code, for debugging dfilter routines.
	dumpcap - Dump network traffic
	editcap - Edit and/or translate the format of capture files
	idl2wrs - CORBA IDL to Wireshark Plugin Generator
	mergecap - Merges two or more capture files into one
	randpkt - Random Packet Generator
	rawshark - Dump and analyze raw libpcap data
	text2pcap - Generate a capture file from an ASCII hexdump of packets
	tshark - Dump and analyze network traffic
	wireshark-filter - Wireshark filter syntax and reference
	wireshark - Interactively dump and analyze network traffic
	
More related projects:
	http://www.tcpdump.org/related.html


