Introduction
------------

[![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome) [![Build Status](https://travis-ci.org/caesar0301/awesome-pcaptools.svg)](https://travis-ci.org/caesar0301/awesome-pcaptools)

This project does not contain any source code or files. I just want to make a list of tools to process pcap files in research of network traffic. For more awesome lists, see https://github.com/sindresorhus/awesome

**License**: Apache License v2.


> * [Linux commands](#linuxcmds)
> * [Traffic Capture](#capture)
> * [Traffic Analysis/Inspection](#analysis)
> * [DNS Utilities](#dnstools)
> * [File Extraction](#fileextraction)
> * [Related Projects](#others)



Linux commands<a name="linuxcmds"></a>
--------------------------------------

* **Bmon**: (Bandwidth Monitor) is a tool similar to nload that shows the traffic load over all the network interfaces on the system. The output also consists of a graph and a section with packet level details. [Screenshot](http://www.binarytides.com/blog/wp-content/uploads/2014/03 /bmon- 640x480.png)

* **Bwm-ng**: (Bandwidth Monitor Next Generation) is another very simple real time network load monitor that reports a summary of the speed at which data is being transferred in and out of all available network interfaces on the system. [Screenshot]()

* **CBM**: (Color Bandwidth Meter) A tiny little simple bandwidth monitor that displays the traffic volume through network interfaces. No further options, just the traffic stats are display and updated in realtime. [Screenshot](http://www.binarytides.com/blog /wp-content/uploads/2014/03/cbm.png)

* **Collectl**: reports system statistics in a style that is similar to dstat, and like dstat it is gathers statistics about various different system resources like cpu, memory, network etc. Over here is a simple example of how to use it to report network usage/bandwidth. [Screenshot]()

* **Dstat**: is a versatile tool (written in python) that can monitor different system statistics and report them in a batch style mode or log the data to a csv or similar file. This example shows how to use dstat to report network bandwidth [Screenshot]()

* **Ifstat**: reports the network bandwidth in a batch style mode. The output is in a format that is easy to log and parse using other programs or utilities. [Screenshot]()

* **Iftop**: measures the data flowing through individual socket connections, and it works in a manner that is different from Nload. Iftop uses the pcap library to capture the packets moving in and out of the network adapter, and then sums up the size and count to find the total bandwidth under use. Although iftop reports the bandwidth used by individual connections, it cannot report the process name/id involved in the particular socket connection. But being based on the pcap library, iftop is able to filter the traffic and report bandwidth usage over selected host connections as specified by the filter. [Screenshot](http://www.binarytides.com/blog/wp-content/uploads/2014/03/iftop.png)

* **Iptraf**: is an interactive and colorful IP Lan monitor. It shows individual connections and the amount of data flowing between the hosts. [Screenshot](http://www.binarytides.com/blog/wp-content/uploads/2014/03/iptraf.png)

* **Jnettop**: [Jnettop](http://jnettop.kubs.info/wiki/) is a traffic visualiser, which captures traffic going through the host it is running from and displays streams sorted by bandwidth they use. [Screenshot](http://jnettop.kubs.info/wiki/?binary=internal%3A%2F%2F76195466cc3bca92f8de7b404e240844.gif)

* **Nethogs**: is a small 'net top' tool that shows the bandwidth used by individual processes and sorts the list putting the most intensive processes on top. In the event of a sudden bandwidth spike, quickly open nethogs and find the process responsible. Nethogs reports the PID, user and the path of the program. [Screenshot](http://www.binarytides.com/blog/wp-content/uploads/2014/03/nethogs.png)

* **Netload**: displays a small report on the current traffic load, and the total number of bytes transferred since the program start. No more features are there. Its part of the netdiag. [Screenshot](http://www.binarytides.com/blog/wp-content/uploads/2014/03/netload.png)

* **Netwatch**: is part of the netdiag collection of tools, and it too displays the connections between local host and other remote hosts, and the speed at which data is transferring on each connection. [Screenshot](http://www.binarytides.com/blog/wp-content/uploads/2014/03/netwatch.png)

* **Nload**: is a commandline tool that allows users to monitor the incoming and outgoing traffic separately. It also draws outa graph to indicate the same, the scale of which can be adjusted. Easy and simple to use, and does not support many options. [Screenshot](http://www.binarytides.com/blog/wp-content/uploads/2014/03/nload.png)

* **Pktstat**: displays all the active connections in real time, and the speed at which data is being transferred through them. It also displays the type of the connection, i.e. tcp or udp and also details about http requests if involved. [Screenshot](http://www.binarytides.com/blog/wp-content/uploads/2014/03/pktstat.png)

* **Slurm**: is 'yet' another network load monitor that shows device statistics along with an ascii graph. It supports 3 different styles of graphs each of which can be activated using the c, s and l keys. Simple in features, slurm does not display any further details about the network load. [Screenshot](http://www.binarytides.com/blog/wp-content/uploads/2014/03/slurm.png)

* **Speedometer**: Another small and simple tool that just draws out good looking graphs of incoming and outgoing traffic through a given interface. [Screenshot](http://www.binarytides.com/blog/wp-content/uploads/2014/03/speedometer.png)

* **Tcptrack**: is similar to iftop, and uses the pcap library to capture packets and calculate various statistics like the bandwidth used in each connection. It also supports the standard pcap filters that can be used to monitor specific connections. [Screenshot](http://www.binarytides.com/blog /wp-content/uploads/2014/03/tcptrack.png)

* **Trafshow**: reports the current active connections, their protocol and the data transfer speed on each connection. It can filter out connections using pcap type filters. [Screenshot](http://www.binarytides.com/blog/wp-content/uploads/2014/03/trafshow.png)

* **Vnstat**: is bit different from most of the other tools. It actually runs a background service/daemon and keeps recording the size of data transfer all the time. Next it can be used to generate a report of the history of network usage. [Screenshot]()



Traffic Capture<a name="capture"></a>
---------------

* [Libpcap/Tcpdump](http://www.tcpdump.org/): The official site of tcpdump, a powerful command-line packet analyzer; and libpcap, a portable C/C++ library for network traffic capture.

* [Ngrep](http://ngrep.sourceforge.net/): strives to provide most of GNU grep's common features, applying them to the network layer. ngrep is a pcap-aware tool that will allow you to specify extended regular or hexadecimal expressions to match against data payloads of packets. It currently recognizes TCP, UDP and ICMP across Ethernet, PPP, SLIP, FDDI, Token Ring and null interfaces, and understands bpf filter logic in the same fashion as more common packet sniffing tools, such as tcpdump and snoop.

* [clj-net-pcap](https://github.com/ruedigergad/clj-net-pcap): `clj-net-pcap` is a packet capturing library for Clojure. clj-net-pcap uses jNetPcap and adds convenience functionality around jNetPcap for easing the usability. A [paper on clj-net-pcap](http://ieeexplore.ieee.org/xpl/articleDetails.jsp?tp=&arnumber=6903107) was published in scope of COMPSACW 2014.

* [jNetPcap](http://jnetpcap.com): jNetPcap is a packet capturing library for Java that is available for Linux and Windows. jNetPcap leverages libpcap respectively WinPcap and employs the Java Native Interface (JNI) for using the functionality provided by libpcap/WinPcap.

* [Moloch](https://github.com/aol/moloch): Moloch is a open source large scale full PCAP capturing, indexing and database system.

* [n2disk](http://www.ntop.org/products/n2disk/) (Commercial): A multi-Gigabit network traffic recorder with indexing capabilities. n2disk is a network traffic recorder application. With n2disk you can capture full- sized network packets at multi-Gigabit rate (above 10 Gigabit/s on adequate hardware) from a live network interface, and write them into files without any packet loss.

* [OpenFPC](http://www.openfpc.org/): OpenFPC is a set of scripts that combine to provide a lightweight full-packet network traffic recorder & buffering tool. Its design goal is to allow non-expert users to deploy a distributed network traffic recorder on COTS hardware while integrating into existing alert and log tools.

* [PF_RING](http://www.ntop.org/products/pf_ring/): PF_RING is a new type of network socket that dramatically improves the packet capture speed. Available for Linux kernels 2.6.32 and newer. No need to patch the kernel. PF_RING-aware drivers for increased packet capture acceleration.

* [TTT](http://www.csl.sony.co.jp/person/kjc/kjc/software.html#ttt): (Tele Traffic Tapper) is yet another descendant of tcpdump but it is capable of real-time, graphical, and remote traffic-monitoring. ttt won't replace tcpdump, rather, it helps you find out what to look into with tcpdump. ttt monitors the network and automatically picks up the main contributors of the traffic within the time window. The graphs are updated every second by default.

* [Yaf](https://tools.netsa.cert.org/yaf/yaf.html): It's a reliable piece of software, quite solid and able to generate flow records from pcap. This is very nice for indexing huge pcap or even doing packet capture. The recent version can even extract payloads and put in the flow records.


Traffic Analysis/Inspection<a name="analysis"></a>
--------------------------------------------------

* [AIEngine](https://bitbucket.org/camp0/aiengine): is a next generation interactive/programmable packet inspection engine with capabilities of learning without any human intervention, NIDS functionality, DNS domain classification, network collector and many others. AIEngine also helps network/security professionals to identify traffic and develop signatures for use them on NIDS, Firewalls, Traffic classifiers and so on.

* [Bro](http://bro-ids.org/): is an open-source, Unix-based Network Intrusion Detection System (NIDS) that passively monitors network traffic and looks for suspicious activity. Bro detects intrusions by first parsing network traffic to extract its application- level semantics and then executing event-oriented analyzers that compare the activity with patterns deemed troublesome. Its analysis includes detection of specific attacks (including those defined by signatures, but also those defined in terms of events) and unusual activities (e.g., certain hosts connecting to certain services, or patterns of failed connection attempts).

* [CapTipper](https://github.com/omriher/CapTipper): Malicious HTTP traffic explorer

* [Chopshop](https://github.com/MITRECND/chopshop): is a MITRE developed framework to aid analysts in the creation and execution of pynids based decoders and detectors of APT tradecraft.

* [CoralReef](http://www.caida.org/tools/measurement/coralreef/): is a software suite developed by CAIDA to analyze data collected by passive Internet traffic monitors. It provides a programming library libcoral, similar to libpcap with extensions for ATM and other network types, which is available from both C and Perl.

* [DPDK](http://dpdk.org/): is a set of libraries and drivers for fast packet processing. It was designed to run on any processors. The first supported CPU was Intel x86 and it is now extended to IBM Power 8, EZchip TILE-Gx and ARM. It runs mostly in Linux userland. A FreeBSD port is available for a subset of DPDK features.

* [DPKT](http://code.google.com/p/dpkt/): Python packet creation/parsing library.

* [ECap](https://bitbucket.org/nathanj/ecap/wiki): (External Capture) is a distributed network sniffer with a web front- end. Ecap was written many years ago in 2005, but a post on the tcpdump-workers mailing list requested a similar application... so here it is. It would be fun to update it and work on it again if there's any interest.

* [EtherApe](http://etherape.sourceforge.net/): is a graphical network monitor for Unix modeled after etherman. Featuring link layer, ip and TCP modes, it displays network activity graphically. Hosts and links change in size with traffic. Color coded protocols display. It supports Ethernet, FDDI, Token Ring, ISDN, PPP and SLIP devices. It can filter traffic to be shown, and can read traffic from a file as well as live from the network.

* [HttpSniffer](https://github.com/caesar0301/http-sniffer): A multi-threading tool to sniff TCP flow statistics and embedded HTTP headers from PCAP file. Each TCP flow carrying HTTP is exported to text file in JSON format.

* [Ipsumdump](http://www.read.seas.harvard.edu/~kohler/ipsumdump/): summarizes TCP/IP dump files into a self-describing ASCII format easily readable by humans and programs. Ipsumdump can read packets from network interfaces, from tcpdump files, and from existing ipsumdump files. It will transparently uncompress tcpdump or ipsumdump files when necessary. It can randomly sample traffic, filter traffic based on its contents, anonymize IP addresses, and sort packets from multiple dumps by timestamp. Also, it can optionally create a tcpdump file containing actual packet data. It's also convenient to work with CLICK as a inserted module.

* [ITA](http://ita.ee.lbl.gov/): The Internet Traffic Archive is a moderated repository to support widespread access to traces of Internet network traffic, sponsored by ACM SIGCOMM. The traces can be used to study network dynamics, usage characteristics, and growth patterns, as well as providing the grist for trace- driven simulations. The archive is also open to programs for reducing raw trace data to more manageable forms, for generating synthetic traces, and for analyzing traces.

* [Libcrafter](http://code.google.com/p/libcrafter/): is a high level library for C++ designed to make easier the creation and decoding of network packets. It is able to craft or decode packets of most common network protocols, send them on the wire, capture them and match requests and replies.

* [Libnet](http://libnet.sourceforge.net/): is a collection of routines to help with the construction and handling of network packets. It provides a portable framework for low-level network packet shaping, handling and injection. Libnet features portable packet creation interfaces at the IP layer and link layer, as well as a host of supplementary and complementary functionality. Using libnet, quick and simple packet assembly applications can be whipped up with little effort.

* [Libnids](http://libnids.sourceforge.net/): designed by Rafal Wojtczuk, is an implementation of an E-component of Network Intrusion Detection System. It emulates the IP stack of Linux 2.0.x. Libnids offers IP defragmentation, TCP stream assembly and TCP port scan detection. The most valuable feature of libnids is reliability. A number of tests were conducted, which proved that libnids predicts behaviour of protected Linux hosts as closely as possible.

* [Multitail](http://www.vanheusden.com/multitail): now has a colorscheme included for monitoring the tcpdump output. It can also filter, convert timestamps to timestrings and much more.

* [Netsniff-ng](www.github.com/borkmann/netsniff-ng): Netsniff-ng is a toolkit of free Linux networking utilities, a Swiss army knife for your daily Linux network plumbing if you will.

* [NetDude](http://netdude.sourceforge.net/): (NETwork DUmp data Displayer and Editor). From their webpage, "it is a GUI-based tool that allows you to make detailed changes to packets in tcpdump tracefiles."

* [Network Expect](http://www.netexpect.org/): is a framework that allows to easily build tools that can interact with network traffic. Following a script, traffic can be injected into the network, and decisions can be taken, and acted upon, based on received network traffic. An interpreted language provides branching and high-level control structures to direct the interaction with the network. Network Expect uses libpcap for packet capture and libwireshark (from the Wireshark project) for packet dissection tasks. (GPL, BSD/Linux/OSX).

* [Ntop](http://www.ntop.org/): Ntop is a network traffic probe that shows the network usage, similar to what the popular top Unix command does. ntop is based on libpcap and it has been written in a portable way in order to virtually run on every Unix platform and on Win32 as well.

* [Ntopng](http://www.ntop.org/products/ntop/): Ntopng is the next generation version of the original ntop, a network traffic probe that shows the network usage, similar to what the popular top Unix command does. ntop is based on libpcap and it has been written in a portable way in order to virtually run on every Unix platform, MacOSX and on Win32 as well.

* [Pcap2har](https://github.com/andrewf/pcap2har): A program to convert .pcap network capture files to HTTP Archive files using library dpkt.

* [pkt2flow](https://github.com/caesar0301/pkt2flow): A simple utility to classify packets into flows. It's so simple that only one task is aimed to finish.  For Deep Packet Inspection or flow classification, it's so common to analyze the feature of one specific flow. I have make the attempt to use made-ready tools like tcpflows, tcpslice, tcpsplit, but all these tools try to either decrease the trace volume (under requirement) or resemble the packets into flow payloads (over requirement). I have not found a simple tool to classify the packets into flows without further processing.

* [potiron](https://github.com/CIRCL/potiron): Normalizes, indexes, enriches and visualizes network captures.

* [pyshark](http://kiminewt.github.io/pyshark/): A Python wrapper for tshark, allowing python packet parsing using wireshark dissectors. There are quite a few python packet parsing modules, this one is different because it doesn't actually parse any packets, it simply uses tshark's (wireshark command-line utility) ability to export XMLs to use its parsing.

* [Sanitize](http://ita.ee.lbl.gov/html/contrib/sanitize.html): Sanitize is a collection of five Bourne shell scripts for reducing tcpdump traces in order to address security and privacy concerns, by renumbering hosts and stripping out packet contents. Each script takes as input a tcpdump trace file and generates to stdout a reduced, ASCII file in fixed-column format.

* [Scapy](http://www.secdev.org/projects/scapy/): Scapy is a powerful interactive packet manipulation program. It is able to forge or decode packets of a wide number of protocols, send them on the wire, capture them, match requests and replies, and much more. It can easily handle most classical tasks like scanning, tracerouting, probing, unit tests, attacks or network discovery (it can replace hping, 85% of nmap, arpspoof, arp-sk, arping, tcpdump, tethereal, p0f, etc.). It also performs very well at a lot of other specific tasks that most other tools can't handle, like sending invalid frames, injecting your own 802.11 frames, combining technics (VLAN hopping+ARP cache poisoning, VOIP decoding on WEP encrypted channel, ...), etc.

* [Sniff](http://www.thedumbterminal.co.uk/software/sniff.html): Makes output from the tcpdump program easier to read and parse.

* [Snort](http://www.snort.org/): Snort is an open source network intrusion prevention and detection system (IDS/IPS) developed by Sourcefire, now owned by Cisco. Combining the benefits of signature, protocol and anomaly- based inspection, Snort is the most widely deployed IDS/IPS technology worldwide. With millions of downloads and approximately 500,000 registered users, Snort has become the de facto standard for IPS.

* [Socket Sentry](http://code.google.com/p/socket-sentry): Socket Sentry is a real-time network traffic monitor for KDE Plasma in the same spirit as tools like iftop and netstat.

* [TCP-Reduce](http://ita.ee.lbl.gov/html/contrib/tcp-reduce.html): TCP-Reduce is a collection of Bourne shell scripts for reducing tcpdump traces to one-line summaries of each TCP connection present in the trace. The scripts look only at TCP SYN/FIN/RST packets. Connections without SYN packets in the trace (such as those on- going at the beginning of the trace) will not appear in the summary. Garbaged packets (those missing some of their contents) are reported to stderr as bogon's and are discarded. Occasionally the script gets fooled by retransmissions with altered sequence numbers, and reports erroneous huge connection sizes - always check large connections (say 100 MB or more) for plausibility.

* [Tcpdpriv](http://ita.ee.lbl.gov/html/contrib/tcpdpriv.html): Tcpdpriv is program for eliminating confidential information (user data and addresses) from packets collected on a network interface (or, from trace files created using the -w argument to tcpdump). Tcpdpriv removes the payload of TCP and UDP, and the entire IP payload for other protocols. It implements several address scrambling methods; the sequential numbering method and its variants, and a hash method with preserving address prefix.

* [Tcpflow](https://github.com/simsong/tcpflow): A program that captures data transmitted as part of TCP connections (flows), and stores the data in a way that is convenient for protocol analysis or debugging. A program like 'tcpdump' shows a summary of packets seen on the wire, but usually doesn't store the data that's actually being transmitted. In contrast, tcpflow reconstructs the actual data streams and stores each flow in a separate file for later analysis. [Original link](http://www.circlemud.org/jelson/software/tcpflow/).

* [Tcplook](http://ita.ee.lbl.gov/html/contrib/tracelook.html): Tracelook is an Tcl/TK program for graphically viewing the contents of trace files created using the -w argument to tcpdump. Tracelook should look at all protocols, but presently only looks at TCP connections. The program is slow and uses system resources prodigiously.

* [Tcpreplay](http://tcpreplay.synfin.net/): Replays a pcap file on an interface using libnet.

* [Tcpslice](ftp://ftp.ee.lbl.gov/tcpslice.tar.gz): Tcpslice is a tool for extracting portions of packet trace files generated using tcpdump's -w flag. It can combine multiple trace files, and/or extract portions of one or more traces based on time. [From the tcpdump CVS server](ftp://ftp.ee.lbl.gov/tcpslice.tar.gz).

* [Tcpsplit](http://www.icir.org/mallman/software/tcpsplit/): A tool to break a single libpcap packet trace into some number of sub- traces, breaking the trace along TCP connection boundaries so that a TCP connection doesn't end up split across two sub-traces. This is useful for making large trace files tractable for in- depth analysis and for subsetting a trace for developing analysis on only part of a trace.

* [Tcpstat](http://www.frenchfries.net/paul/tcpstat/): Tcpstat reports certain network interface statistics much like vmstat does for system statistics. tcpstat gets its information by either monitoring a specific interface, or by reading previously saved tcpdump data from a file.

* [Tcptrace](http://tcptrace.org/index.html): A tool written by Shawn Ostermann at Ohio University, for analysis of TCP dump files. It can take as input the files produced by several popular packet- capture programs, including tcpdump, snoop, etherpeek, HP Net Metrix, and WinDump. tcptrace can produce several different types of output containing information on each connection seen, such as elapsed time, bytes and segments sent and received, retransmissions, round trip times, window advertisements, throughput, and more. It can also produce a number of graphs for further analysis.

* [TraceWrangler](https://www.tracewrangler.com/): TraceWrangler is a network capture file toolkit running on Windows (or on Linux, using WINE) that supports PCAP as well as the new PCAPng file format, which is now the standard file format used by Wireshark. The most prominent use case for TraceWrangler is the easy sanitization and anonymization of PCAP and PCAPng files (sometimes called "trace files", "capture files" or "packet captures"), removing or replacing sensitive data while being easy to use.

* [Tstat](http://tstat.tlc.polito.it/): A passive sniffer able to provide several insight on the traffic patterns at both the network and transport levels with a tremendous set of flow features.

* [WAND](http://research.wand.net.nz/): A wonderful collection of tools built on libtrace to process network traffic, which is from The University of Waikato. I love this project!

* [WinPcap](http://www.tcpdump.org/wpcap.html): An extract of a message from Guy Harris on state of WinPcap and WinDump.

* [Wireshark suit](http://wiki.wireshark.org/Tools): The well-known tool suit to support packet analyzer and protocol decoder. It also includes a few practical tools and scripts to support most of the common usage.

* [Xplot](http://www.xplot.org/): The program xplot was written in the late 1980s to support the analysis of TCP packet traces.

* [yaraPcap](https://github.com/kevthehermit/YaraPcap): Process HTTP Pcaps With YARA

* [yaraprocessor](https://github.com/MITRECND/yaraprocessor): With yaraprocessor YARA can be run against individual packet payloads as well as a concatenation of some or all of the payloads. It was originally written for use in Chopshop, but can also be used without it.


DNS Utilities <a name="dnstools"></a>
--------------------------------------------

* [dnsgram](https://doc.powerdns.com/md/manpages/dnsgram.1/): dnsgram is a debugging tool for intermittent resolver failures. it takes one or more input PCAP files and generates statistics on 5 second segments allowing the study of intermittent resolver issues.

* [dnsreplay](https://doc.powerdns.com/md/manpages/dnsreplay.1/): Dnsreplay takes recorded questions and answers and replays them to the specified nameserver and reporting afterwards which percentage of answers matched, were worse or better. Then compares the answers and some other metrics with the actual ones with those found in the dumpfile.

* [dnsscan](https://doc.powerdns.com/md/manpages/dnsscan.1/): dnsscan takes one or more INFILEs in PCAP format and generates a list of the number of queries per query type.

* [dnsscope](https://doc.powerdns.com/md/manpages/dnsscope.1/): dnsscope takes an input PCAP and generates some simple statistics outputs these to console.

* [dnswasher](https://doc.powerdns.com/md/manpages/dnswasher.1/): dnswasher takes an input file in PCAP format and writes out a PCAP file, while obfuscating end-user IP addresses. This is useful to share data with third parties while attempting to protect the privacy of your users.


File Extraction<a name="fileextraction"></a>
--------------------------------------------

* [Chaosreader](http://chaosreader.sourceforge.net/): A freeware tool to trace TCP/UDP/... sessions and fetch application data from snoop or tcpdump logs. This is a type of "any-snarf" program, as it will fetch telnet sessions, FTP files, HTTP transfers (HTML, GIF, JPEG, ...), SMTP emails, ... from the captured data inside network traffic logs. A html index file is created that links to all the session details, including realtime replay programs for telnet, rlogin, IRC, X11 and VNC sessions; and reports such as image reports and HTTP GET/POST content reports.

* [Dsniff](http://www.monkey.org/~dugsong/dsniff/): Dsniff is a collection of tools for network auditing and penetration testing. dsniff, filesnarf, mailsnarf, msgsnarf, urlsnarf, and webspy passively monitor a network for interesting data (passwords, e-mail, files, etc.). arpspoof, dnsspoof, and macof facilitate the interception of network traffic normally unavailable to an attacker (e.g, due to layer-2 switching). sshmitm and webmitm implement active monkey-in-the-middle attacks against redirected SSH and HTTPS sessions by exploiting weak bindings in ad-hoc PKI.

* [Foremost](http://foremost.sourceforge.net/): is a console program to recover files based on their headers, footers, and internal data structures. This process is commonly referred to as data carving. Foremost can work on image files, such as those generated by dd, Safeback, Encase, etc, or directly on a drive. The headers and footers can be specified by a configuration file or you can use command line switches to specify built-in file types. These built-in types look at the data structures of a given file format allowing for a more reliable and faster recovery.

* [Justniffer](http://justniffer.sourceforge.net/): Justniffer is a network protocol analyzer that captures network traffic and produces logs in a customized way, can emulate Apache web server log files, track response times and extract all "intercepted" files from the HTTP traffic.

* [NetworkMiner](http://www.netresec.com/?page=NetworkMiner): NetworkMiner is a Network Forensic Analysis Tool (NFAT) for Windows (but also works in Linux / Mac OS X / FreeBSD). NetworkMiner can be used as a passive network sniffer/packet capturing tool in order to detect operating systems, sessions, hostnames, open ports etc. without putting any traffic on the network. NetworkMiner can also parse PCAP files for off-line analysis and to regenerate/ reassemble transmitted files and certificates from PCAP files.

* [pcapfex](https://github.com/vikwin/pcapfex) - Packet CAPture Forensic Evidence eXtractor (pcapfex) is a tool that finds and extracts files from packet capture files. Its power lies in its ease of use. Just provide it a pcap file, and it will try to extract all of the files. It is an extensible platform, so additional file types to recognize and extract can be added easily.

* [scalpel](https://github.com/sleuthkit/scalpel): Scalpel is an open source data carving tool.

* [Snort](http://www.snort.org/): is an open source network intrusion prevention and detection system (IDS/IPS) developed by Sourcefire, now owned by Cisco. Combining the benefits of signature, protocol and anomaly- based inspection, Snort is the most widely deployed IDS/IPS technology worldwide.

* [Tcpick](http://tcpick.sourceforge.net/): is a textmode sniffer libpcap-based that can track, reassemble and reorder tcp streams. Tcpick is able to save the captured flows in different files or displays them in the terminal, and so it is useful to sniff files that are transmitted via ftp or http. It can display all the stream on the terminal, when the connection is closed in different display modes like hexdump, hexdump + ascii, only printable characters, raw mode and so on.

* [Tcpxtract](http://tcpxtract.sourceforge.net/): is a tool for extracting files from network traffic based on file signatures. Extracting files based on file type headers and footers (sometimes called "carving") is an age old data recovery technique.

* [Xplico](http://www.xplico.org/about): The goal of Xplico is extract from an internet traffic capture the applications data contained. For example, from a pcap file Xplico extracts each email (POP, IMAP, and SMTP protocols), all HTTP contents, each VoIP call (SIP), FTP, TFTP, and so on. Xplico isn't a network protocol analyzer. Xplico is an open source Network Forensic An alysis Tool (NFAT). Xplico is released under the GNU General Public License and with some scripts under Creative Commons Attribution-NonCommercial-ShareAlike 3.0 Unported (CC BY-NC-SA 3.0) License.



Related Projects<a name="others"></a>
--------------------------------------

* [BPF for Ultrix](http://www.tcpdump.org/other/bpfext42.tar.Z): A distribution of BPF for Ultrix 4.2, with both source code and binary modules.

* [BPF+](http://www.cs.berkeley.edu/~abegel/sigcomm99/bpf+.ps): Exploiting Global Data-flow Optimization in a Generalized Packet Filter Architecture By Andrew Begel, Steven McCanne, and Susan Graham.

* [FFT-FGN-C](http://ita.ee.lbl.gov/html/contrib/fft_fgn_c.html): is a program for synthesizing a type of self-similar process known as fractional Gaussian noise. The program is fast but approximate. Fractional Gaussian noise is only one type of self-similar process. When using this program for synthesizing network traffic, you must keep in mind that it may be that the traffic you seek is better modeled using one of the other processes.

* [Haka](http://www.haka-security.org/): An open source security oriented language which allows to describe protocols and apply security policies on (live) captured traffic. The scope of Haka language is twofold. First of all, it allows to write security rules in order to filter/alter/drop unwanted packets and log and report malicious activities. Second, Haka features a grammar enabling to specify network protocols and their underlying state machine.

* [RIPE-NCC Hadoop for PCAP](https://github.com/RIPE-NCC/hadoop-pcap): A Hadoop library to read packet capture (PCAP) files. Bundles the code used to read PCAPs. Can be used within MapReduce jobs to natively read PCAP files. Also features a Hive Serializer/Deserializer (SerDe) to query PCAPs using SQL like commands.

* [Traffic Data Repository at the WIDE Project](http://www.sonycsl.co.jp/person/kjc/papers/freenix2000/): It becomes increasingly important for both network researchers and operators to know the trend of network traffic and to find anomaly in their network traffic. This paper describes an on-going effort within the WIDE project to collect a set of free tools to build a traffic data repository containing detailed information of our backbone traffic. Traffic traces are collected by tcpdump and, after removing privacy information, the traces are made open to the public. We review the issues on user privacy, and then, the tools used to build the WIDE traffic repository. We will report the current status and findings in the early stage of our IPv6 deployment.

* [Usenix93 Paper on BPF](ftp://ftp.ee.lbl.gov/papers/bpf-usenix93.ps.Z): The libpcap interface supports a filtering mechanism based on the architecture in the BSD packet filter. BPF is described in the 1993 Winter Usenix paper "The BSD Packet Filter: A New Architecture for User-level Packet Capture".
