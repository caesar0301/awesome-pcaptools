Introduction [![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)
------------

This project dose not contain any source code or files. I just want to make a
list of tools to process pcap files in research of network traffic. Items with
notation `(R)` indicate recommendations in specific categories. For more
awesome lists, see https://github.com/sindresorhus/awesome

> * [Linux commands](#linuxcmds)
> * [Traffic Capture](#capture)
> * [Traffic Analysis/Inspection](#analysis)
> * [File Extraction](#fileextraction)
> * [Other Projects](#others)

Linux commands<a name="linuxcmds"></a>
--------------------------------------

* Nload

    Nload is a commandline tool that allows users to monitor the incoming and
outgoing traffic separately. It also draws outa graph to indicate the same, the
scale of which can be adjusted. Easy and simple to use, and does not support
many options. [Screenshot](http://www.binarytides.com/blog/wp-
content/uploads/2014/03/nload.png)

* Iftop

    Iftop measures the data flowing through individual socket connections, and
it works in a manner that is different from Nload. Iftop uses the pcap library
to capture the packets moving in and out of the network adapter, and then sums
up the size and count to find the total bandwidth under use. Although iftop
reports the bandwidth used by individual connections, it cannot report the
process name/id involved in the particular socket connection. But being based
on the pcap library, iftop is able to filter the traffic and report bandwidth
usage over selected host connections as specified by the filter.
[Screenshot](http://www.binarytides.com/blog/wp-
content/uploads/2014/03/iftop.png)

* Jnettop

    [Jnettop](http://jnettop.kubs.info/wiki/) is a traffic visualiser, which captures traffic going through the host it is running from and displays streams sorted by bandwidth they use. [Screenshot](http://jnettop.kubs.info/wiki/?binary=internal%3A%2F%2F76195466cc3bca92f8de7b404e240844.gif)

* Iptraf

    Iptraf is an interactive and colorful IP Lan monitor. It shows individual
connections and the amount of data flowing between the hosts.
[Screenshot](http://www.binarytides.com/blog/wp-
content/uploads/2014/03/iptraf.png)

* Nethogs

    Nethogs is a small 'net top' tool that shows the bandwidth used by
individual processes and sorts the list putting the most intensive processes on
top. In the event of a sudden bandwidth spike, quickly open nethogs and find
the process responsible. Nethogs reports the PID, user and the path of the
program. [Screenshot](http://www.binarytides.com/blog/wp-
content/uploads/2014/03/nethogs.png)

* Bmon

    Bmon (Bandwidth Monitor) is a tool similar to nload that shows the traffic
load over all the network interfaces on the system. The output also consists of
a graph and a section with packet level details.
[Screenshot](http://www.binarytides.com/blog/wp-content/uploads/2014/03 /bmon-
640x480.png)

* Slurm

    Slurm is 'yet' another network load monitor that shows device statistics
along with an ascii graph. It supports 3 different styles of graphs each of
which can be activated using the c, s and l keys. Simple in features, slurm
does not display any further details about the network load.
[Screenshot](http://www.binarytides.com/blog/wp-
content/uploads/2014/03/slurm.png)

* Tcptrack

    Tcptrack is similar to iftop, and uses the pcap library to capture packets
and calculate various statistics like the bandwidth used in each connection. It
also supports the standard pcap filters that can be used to monitor specific
connections. [Screenshot](http://www.binarytides.com/blog /wp-
content/uploads/2014/03/tcptrack.png)

* Vnstat

    Vnstat is bit different from most of the other tools. It actually runs a
background service/daemon and keeps recording the size of data transfer all the
time. Next it can be used to generate a report of the history of network usage.
[Screenshot]()

* Bwm-ng

    Bwm-ng (Bandwidth Monitor Next Generation) is another very simple real time
network load monitor that reports a summary of the speed at which data is being
transferred in and out of all available network interfaces on the system.
[Screenshot]()

* CBM (Color Bandwidth Meter)

    A tiny little simple bandwidth monitor that displays the traffic volume
through network interfaces. No further options, just the traffic stats are
display and updated in realtime. [Screenshot](http://www.binarytides.com/blog
/wp-content/uploads/2014/03/cbm.png)

* Speedometer

    Another small and simple tool that just draws out good looking graphs of
incoming and outgoing traffic through a given interface.
[Screenshot](http://www.binarytides.com/blog/wp-
content/uploads/2014/03/speedometer.png)

* Pktstat

    Pktstat displays all the active connections in real time, and the speed at
which data is being transferred through them. It also displays the type of the
connection, i.e. tcp or udp and also details about http requests if involved.
[Screenshot](http://www.binarytides.com/blog/wp-
content/uploads/2014/03/pktstat.png)

* Netwatch

    Netwatch is part of the netdiag collection of tools, and it too displays
the connections between local host and other remote hosts, and the speed at
which data is transferring on each connection.
[Screenshot](http://www.binarytides.com/blog/wp-
content/uploads/2014/03/netwatch.png)

* Trafshow

    Like netwatch and pktstat, trafshow reports the current active connections,
their protocol and the data transfer speed on each connection. It can filter
out connections using pcap type filters.
[Screenshot](http://www.binarytides.com/blog/wp-
content/uploads/2014/03/trafshow.png)

* Netload

    The netload command just displays a small report on the current traffic
load, and the total number of bytes transferred since the program start. No
more features are there. Its part of the netdiag.
[Screenshot](http://www.binarytides.com/blog/wp-
content/uploads/2014/03/netload.png)

* Ifstat

    The ifstat reports the network bandwidth in a batch style mode. The output
is in a format that is easy to log and parse using other programs or utilities.
[Screenshot]()

* Dstat

    Dstat is a versatile tool (written in python) that can monitor different
system statistics and report them in a batch style mode or log the data to a
csv or similar file. This example shows how to use dstat to report network
bandwidth [Screenshot]()

* Collectl

    Collectl reports system statistics in a style that is similar to dstat, and
like dstat it is gathers statistics about various different system resources
like cpu, memory, network etc. Over here is a simple example of how to use it
to report network usage/bandwidth. [Screenshot]()

Traffic Capture<a name="capture"></a>
---------------

* Libpcap/Tcpdump `(R)`

    The official site of tcpdump, a powerful command-line packet analyzer; and
libpcap, a portable C/C++ library for network traffic capture.
(http://www.tcpdump.org/)

* Ngrep

    Ngrep strives to provide most of GNU grep's common features, applying them
to the network layer. ngrep is a pcap-aware tool that will allow you to specify
extended regular or hexadecimal expressions to match against data payloads of
packets. It currently recognizes TCP, UDP and ICMP across Ethernet, PPP, SLIP,
FDDI, Token Ring and null interfaces, and understands bpf filter logic in the
same fashion as more common packet sniffing tools, such as tcpdump and snoop.
(http://www.packetfactory.net/Projects/ngrep)

* TTT: Tele Traffic Tapper

    TTT is yet another descendant of tcpdump but it is capable of real-time,
graphical, and remote traffic-monitoring. ttt won't replace tcpdump, rather, it
helps you find out what to look into with tcpdump. ttt monitors the network and
automatically picks up the main contributors of the traffic within the time
window. The graphs are updated every second by default.
(http://www.csl.sony.co.jp/person/kjc/kjc/software.html#ttt)

* n2disk (Commercial)

    A multi-Gigabit network traffic recorder with indexing capabilities. n2disk
is a network traffic recorder application. With n2disk you can capture full-
sized network packets at multi-Gigabit rate (above 10 Gigabit/s on adequate
hardware) from a live network interface, and write them into files without any
packet loss. n2disk has been designed to write files into disks for very long
periods, you have to specify a maximum number of distinct file that may be
written during the execution, and if n2disk reaches the maximum number of
files, it will start recycling the files from the oldest one. This way you can
have a complete view of the traffic for a fixed temporal window ...
(http://www.ntop.org/products/n2disk/)

* PF_RING

    PF_RING is a new type of network socket that dramatically improves the
packet capture speed, and that’s characterized by the following properties:
Available for Linux kernels 2.6.32 and newer. No need to patch the kernel: just
load the kernel module. PF_RING-aware drivers for increased packet capture
acceleration. ... (http://www.ntop.org/products/pf_ring/)

* jNetPcap

    jNetPcap is a packet capturing library for Java that is available for Linux
and Windows. jNetPcap leverages libpcap respectively WinPcap and employs the
Java Native Interface (JNI) for using the functionality provided by
libpcap/WinPcap. (http://jnetpcap.com)

* clj-net-pcap

    clj-net-pcap is a packet capturing library for Clojure. clj-net-pcap uses
jNetPcap and adds convenience functionality around jNetPcap for easing the
usability. A paper about clj-net-pcap was published in scope of COMPSACW 2014:
http://ieeexplore.ieee.org/xpl/articleDetails.jsp?tp=&arnumber=6903107
(https://github.com/ruedigergad/clj-net-pcap)

Traffic Analysis/Inspection<a name="analysis"></a>
--------------------------------------------------

* Wireshark suit `(R)`

    The well-konwn tool suit to support packet analyzer and protocol decoder.
(http://www.wireshark.org/) It also includes a few practical tools and scripts
to support most of the common usage. Here is a brief list of these tools
(http://wiki.wireshark.org/Tools)

* WAND

    A wonderful collection of tools built on libtrace to process network
traffic, which is from The University of Waikato. I love this project!
http://research.wand.net.nz/

* Tcptrace `(R)`

    A tool written by Shawn Ostermann at Ohio University, for analysis of TCP
dump files. It can take as input the files produced by several popular packet-
capture programs, including tcpdump, snoop, etherpeek, HP Net Metrix, and
WinDump. tcptrace can produce several different types of output containing
information on each connection seen, such as elapsed time, bytes and segments
sent and recieved, retransmissions, round trip times, window advertisements,
throughput, and more. It can also produce a number of graphs for further
analysis. http://tcptrace.org/index.html

* Tstat `(R)`

    A passive sniffer able to provide several insight on the traffic patterns
at both the network and transport levels with a tremendous set of flow
features. http://tstat.tlc.polito.it/

* Tcpsplit `(R)`

    A tool to break a single libpcap packet trace into some number of sub-
traces, breaking the trace along TCP connection boundaries so that a TCP
connection doesn't end up split across two sub-traces. This is useful for
making large trace files tractable for in- depth analysis and for subsetting a
trace for developing analysis on only part of a trace.
http://www.icir.org/mallman/software/tcpsplit/

* Tcpflow `(R)`

    A program that captures data transmitted as part of TCP connections
(flows), and stores the data in a way that is convenient for protocol analysis
or debugging. A program like 'tcpdump' shows a summary of packets seen on the
wire, but usually doesn't store the data that's actually being transmitted. In
contrast, tcpflow reconstructs the actual data streams and stores each flow in
a separate file for later analysis. (Original)
http://www.circlemud.org/jelson/software/tcpflow/ or (Newest)
https://github.com/simsong/tcpflow

* Tcpreplay

    Replays a pcap file on an interface using libnet.
    http://tcpreplay.synfin.net/

* Tcpstat

    Tcpstat reports certain network interface statistics much like vmstat does
for system statistics. tcpstat gets its information by either monitoring a
specific interface, or by reading previously saved tcpdump data from a file.
http://www.frenchfries.net/paul/tcpstat/

* Tcplook

    Tracelook is an Tcl/TK program for graphically viewing the contents of
trace files created using the -w argument to tcpdump. Tracelook should look at
all protocols, but presently only looks at TCP connections. The program is slow
and uses system resources prodigiously.
http://ita.ee.lbl.gov/html/contrib/tracelook.html

* Tcpdpriv

    Tcpdpriv is program for eliminating confidential information (user data and
addresses) from packets collected on a network interface (or, from trace files
created using the -w argument to tcpdump). Tcpdpriv removes the payload of TCP
and UDP, and the entire IP payload for other protocols. It implements several
address scrambling methods; the sequential numbering method and its variants,
and a hash method with preserving address prefix.
http://ita.ee.lbl.gov/html/contrib/tcpdpriv.html

* Tcpslice

    Tcpslice is a tool for extracting portions of packet trace files generated
using tcpdump's -w flag. It can combine multiple trace files, and/or extract
portions of one or more traces based on time. TCPslice originally comes from:
ftp://ftp.ee.lbl.gov/tcpslice.tar.gz also mirrored here. tcpslice can also be
found in the tcpdump CVS server, as the project tcpslice.
ftp://ftp.ee.lbl.gov/tcpslice.tar.gz

* TCP-Reduce

    TCP-Reduce is a collection of Bourne shell scripts for reducing tcpdump
traces to one-line summaries of each TCP connection present in the trace. The
scripts look only at TCP SYN/FIN/RST packets. Connections without SYN packets
in the trace (such as those on-going at the beginning of the trace) will not
appear in the summary. Garbaged packets (those missing some of their contents)
are reported to stderr as bogon's and are discarded. Occasionally the script
gets fooled by retransmissions with altered sequence numbers, and reports
erroneous huge connection sizes - always check large connections (say 100 MB or
more) for plausibility. http://ita.ee.lbl.gov/html/contrib/tcp-reduce.html

* dpkt

    Python packet creation/parsing library. http://code.google.com/p/dpkt/

* Pcap2har

    A program to convert .pcap network capture files to HTTP Archive files
using library dpkt. https://github.com/andrewf/pcap2har

* Libnet

    Libnet is a collection of routines to help with the construction and
handling of network packets. It provides a portable framework for low-level
network packet shaping, handling and injection. Libnet features portable packet
creation interfaces at the IP layer and link layer, as well as a host of
supplementary and complementary functionality. Using libnet, quick and simple
packet assembly applications can be whipped up with little effort.
http://www.packetfactory.net/Projects/Libnet/

* Libnids

    Libnids, designed by Rafal Wojtczuk, is an implementation of an E-component
of Network Intrusion Detection System. It emulates the IP stack of Linux 2.0.x.
Libnids offers IP defragmentation, TCP stream assembly and TCP port scan
detection. The most valuable feature of libnids is reliability. A number of
tests were conducted, which proved that libnids predicts behaviour of protected
Linux hosts as closely as possible. http://libnids.sourceforge.net/

* ECap

    Ecap (external capture) is a distributed network sniffer with a web front-
end. Ecap was written many years ago in 2005, but a post on the tcpdump-workers
mailing list requested a similar application... so here it is. It would be fun
to update it and work on it again if there's any interest.
https://bitbucket.org/nathanj/ecap/wiki

* HttpSniffer

    A multi-threading tool to sniff TCP flow statistics and embedded HTTP
headers from PCAP file. Each TCP flow carrying HTTP is exported to text file in
JSON format. https://github.com/caesar0301/http-sniffer

* AIEngine

    AIEngine is a next generation interactive/programmable packet inspection
engine with capabilities of learning without any human intervention, NIDS
functionality, DNS domain classification, network collector and many others.
AIEngine also helps network/security professionals to identify traffic and
develop signatures for use them on NIDS, Firewalls, Traffic classifiers and so
on. Available on https://bitbucket.org/camp0/aiengine

* Network Expect

    Network Expect is a framework that allows to easily build tools that can
interact with network traffic. Following a script, traffic can be injected into
the network, and decisions can be taken, and acted upon, based on received
network traffic. An interpreted language provides branching and high-level
control structures to direct the interaction with the network. Network Expect
uses libpcap for packet capture and libwireshark (from the Wireshark project)
for packet dissection tasks. (GPL, BSD/Linux/OSX) Submitted by: Eloy Paris
{peloy at chapus.net} http://www.netexpect.org/

* Socket Sentry

    Socket Sentry is a real-time network traffic monitor for KDE Plasma in the
same spirit as tools like iftop and netstat. Submitted by: Rob Hasselbaum {rob
at hasselbaum.net} http://code.google.com/p/socket-sentry

* Sniff

    Makes output from the tcpdump program easier to read and parse.
http://www.thedumbterminal.co.uk/software/sniff.html

* EtherApe

    EtherApe is a graphical network monitor for Unix modeled after etherman.
Featuring link layer, ip and TCP modes, it displays network activity
graphically. Hosts and links change in size with traffic. Color coded protocols
display. It supports Ethernet, FDDI, Token Ring, ISDN, PPP and SLIP devices. It
can filter traffic to be shown, and can read traffic from a file as well as
live from the network. http://etherape.sourceforge.net/

* Snort

    Snort is an open source network intrusion prevention and detection system
(IDS/IPS) developed by Sourcefire, now owned by Cisco. Combining the benefits of signature,
protocol and anomaly- based inspection, Snort is the most widely deployed
IDS/IPS technology worldwide. With millions of downloads and approximately
500,000 registered users, Snort has become the de facto standard for IPS.
http://www.snort.org/

* Scapy

    Scapy is a powerful interactive packet manipulation program. It is able to
forge or decode packets of a wide number of protocols, send them on the wire,
capture them, match requests and replies, and much more. It can easily handle
most classical tasks like scanning, tracerouting, probing, unit tests, attacks
or network discovery (it can replace hping, 85% of nmap, arpspoof, arp-sk,
arping, tcpdump, tethereal, p0f, etc.). It also performs very well at a lot of
other specific tasks that most other tools can't handle, like sending invalid
frames, injecting your own 802.11 frames, combining technics (VLAN hopping+ARP
cache poisoning, VOIP decoding on WEP encrypted channel, ...), etc.
http://www.secdev.org/projects/scapy/

* Bro

    Bro is an open-source, Unix-based Network Intrusion Detection System (NIDS)
that passively monitors network traffic and looks for suspicious activity. Bro
detects intrusions by first parsing network traffic to extract its application-
level semantics and then executing event-oriented analyzers that compare the
activity with patterns deemed troublesome. Its analysis includes detection of
specific attacks (including those defined by signatures, but also those defined
in terms of events) and unusual activities (e.g., certain hosts connecting to
certain services, or patterns of failed connection attempts). http://bro-
ids.org/

* Ntop

    Ntop is a network traffic probe that shows the network usage, similar to
what the popular top Unix command does. ntop is based on libpcap and it has
been written in a portable way in order to virtually run on every Unix platform
and on Win32 as well. http://www.ntop.org/

* CoralReef

    CoralReef is a software suite developed by CAIDA to analyze data collected
by passive Internet traffic monitors. It provides a programming library
libcoral, similar to libpcap with extensions for ATM and other network types,
which is available from both C and Perl. The software presently supports
dedicated PC boxes using OC3mon and OC12mon cards that collect traffic data in
real time, as well as reading from pcap tracefiles. Version 3.4 to be released
soon supports listening via bpf enabled devices. CoralReef includes drivers,
analysis, web report generation, examples, and capture software. This package
is maintained by CAIDA developers with the support and collaboration of the
Internet measurement community.
http://www.caida.org/tools/measurement/coralreef/

* Xplot

    The program xplot was written in the late 1980s to support the analysis of
TCP packet traces. http://www.xplot.org/

* Multitail

    MultiTail now has a colorscheme included for monitoring the tcpdump output.
It can also filter, convert timestamps to timestrings and much more.
http://www.vanheusden.com/multitail

* Netsniff-ng

    Netsniff-ng is a toolkit of free Linux networking utilities, a Swiss army
knife for your daily Linux network plumbing if you will. http://netsniff-
ng.org/ or on [GitHub](www.github.com/borkmann/netsniff-ng).

* NetDude

    Netdude (NETwork DUmp data Displayer and Editor). From their webpage, "it
is a GUI-based tool that allows you to make detailed changes to packets in
tcpdump tracefiles." http://netdude.sourceforge.net/

* Libcrafter

    Libcrafter is a high level library for C++ designed to make easier the
creation and decoding of network packets. It is able to craft or decode packets
of most common network protocols, send them on the wire, capture them and match
requests and replies. Submitted by: Esteban Pellegrino
http://code.google.com/p/libcrafter/

* WinPcap info

    An extract of a message from Guy Harris on state of WinPcap and WinDump.
http://www.tcpdump.org/wpcap.html

* Sniffer

    The Sniffer product family covers different fields of application
(Distributed, Portable and Wireless Environment). Sniffer solutions monitor,
troubleshoot, analyze, report on, and proactively manage network performance.
They ensure peak performance throughout the enterprise infrastructure, across
all LAN, WAN and high-speed topologies, from 10/100 Ethernet to the latest
high-speed Asynchronous ATM, Gigabit, and Packet-over-SONET (PoS) backbones.
http://www.sniffer.com/products/sniffer-basic/default.asp?A=2

* Traffic Data Repository at the WIDE Project

    It becomes increasingly important for both network researchers and
operators to know the trend of network traffic and to find anomaly in their
network traffic. This paper describes an on-going effort within the WIDE
project to collect a set of free tools to build a traffic data repository
containing detailed information of our backbone traffic. Traffic traces are
collected by tcpdump and, after removing privacy information, the traces are
made open to the public. We review the issues on user privacy, and then, the
tools used to build the WIDE traffic repository. We will report the current
status and findings in the early stage of our IPv6 deployment.
http://www.sonycsl.co.jp/person/kjc/papers/freenix2000/

* ITA: Internet Traffic Archive

    The Internet Traffic Archive is a moderated repository to support
widespread access to traces of Internet network traffic, sponsored by ACM
SIGCOMM. The traces can be used to study network dynamics, usage
characteristics, and growth patterns, as well as providing the grist for trace-
driven simulations. The archive is also open to programs for reducing raw trace
data to more manageable forms, for generating synthetic traces, and for
analyzing traces. http://www.sigcomm.org/ITA/

* Sanitize

    Sanitize is a collection of five Bourne shell scripts for reducing tcpdump
traces in order to address security and privacy concerns, by renumbering hosts
and stripping out packet contents. Each script takes as input a tcpdump trace
file and generates to stdout a reduced, ASCII file in fixed-column format.
http://ita.ee.lbl.gov/html/contrib/sanitize.html

* Ipsumdump (posted by adulau 2012-12-25)

    The ipsumdump program summarizes TCP/IP dump files into a self-describing
ASCII format easily readable by humans and programs. Ipsumdump can read packets
from network interfaces, from tcpdump files, and from existing ipsumdump files.
It will transparently uncompress tcpdump or ipsumdump files when necessary. It
can randomly sample traffic, filter traffic based on its contents, anonymize IP
addresses, and sort packets from multiple dumps by timestamp. Also, it can
optionally create a tcpdump file containing actual packet data. It's also
convinient to work with CLICK as a inserted module. For more info, please read:
http://www.read.seas.harvard.edu/~kohler/ipsumdump/

* Ntopng

    Ntopng is the next generation version of the original ntop, a network
  traffic probe that shows the network usage, similar to what the popular top
  Unix command does. ntop is based on libpcap and it has been written in a
  portable way in order to virtually run on every Unix platform, MacOSX and on
  Win32 as well. (http://www.ntop.org/products/ntop/)
  
  
  
* dnsreplay

    Dnsreplay takes recorded questions and answers and replays them to the 
specified nameserver and reporting afterwards which percentage of answers
matched, were worse or better. Then compares the answers and some other 
metrics with the actual ones with those found in the dumpfile.
https://doc.powerdns.com/md/manpages/dnsreplay.1/

* dnsscan

    dnsscan takes one or more INFILEs in PCAP format and generates a list 
of the number of queries per query type. https://doc.powerdns.com/md/manpages/dnsscan.1/

File Extraction<a name="fileextraction"></a>
----------------------------------------

* Xplico

    The goal of Xplico is extract from an internet traffic capture the
applications data contained. For example, from a pcap file Xplico extracts each
email (POP, IMAP, and SMTP protocols), all HTTP contents, each VoIP call (SIP),
FTP, TFTP, and so on. Xplico isn't a network protocol analyzer. Xplico is an
open source Network Forensic An alysis Tool (NFAT). Xplico is released under
the GNU General Public License and with some scripts under Creative Commons
Attribution-NonCommercial-ShareAlike 3.0 Unported (CC BY-NC-SA 3.0) License.
http://www.xplico.org/about

* Justniffer

    Justniffer is a network protocol analyzer that captures network traffic and
produces logs in a customized way, can emulate Apache web server log files,
track response times and extract all "intercepted" files from the HTTP traffic.
http://justniffer.sourceforge.net/

* NetworkMiner

    NetworkMiner is a Network Forensic Analysis Tool (NFAT) for Windows (but
also works in Linux / Mac OS X / FreeBSD). NetworkMiner can be used as a
passive network sniffer/packet capturing tool in order to detect operating
systems, sessions, hostnames, open ports etc. without putting any traffic on
the network. NetworkMiner can also parse PCAP files for off-line analysis and
to regenerate/ reassemble transmitted files and certificates from PCAP files.
http://www.netresec.com/?page=NetworkMiner

* Tcpxtract

    Tcpxtract is a tool for extracting files from network traffic based on file
signatures. Extracting files based on file type headers and footers (sometimes
called "carving") is an age old data recovery technique. Tools like Foremost
employ this technique to recover files from arbitrary data streams. Tcpxtract
uses this technique specifically for the application of intercepting files
transmitted across a network. Other tools that fill a similar need are driftnet
and EtherPEG. driftnet and EtherPEG are tools for monitoring and extracting
graphic files on a network and is commonly used by network administrators to
police the internet activity of their users. The major limitations of driftnet
and EtherPEG is that they only support three filetypes with no easy way of
adding more. The search technique they use is also not scalable and does not
search across packet boundries. tcpxtract features the following:
http://tcpxtract.sourceforge.net/

* Foremost

    Foremost is a console program to recover files based on their headers,
footers, and internal data structures. This process is commonly referred to as
data carving. Foremost can work on image files, such as those generated by dd,
Safeback, Encase, etc, or directly on a drive. The headers and footers can be
specified by a configuration file or you can use command line switches to
specify built-in file types. These built-in types look at the data structures
of a given file format allowing for a more reliable and faster recovery.
http://foremost.sourceforge.net/

* Dsniff

    Dsniff is a collection of tools for network auditing and penetration
testing. dsniff, filesnarf, mailsnarf, msgsnarf, urlsnarf, and webspy passively
monitor a network for interesting data (passwords, e-mail, files, etc.).
arpspoof, dnsspoof, and macof facilitate the interception of network traffic
normally unavailable to an attacker (e.g, due to layer-2 switching). sshmitm
and webmitm implement active monkey-in-the-middle attacks against redirected
SSH and HTTPS sessions by exploiting weak bindings in ad-hoc PKI.
http://www.monkey.org/~dugsong/dsniff/

* Chaosreader

    A freeware tool to trace TCP/UDP/... sessions and fetch application data
from snoop or tcpdump logs. This is a type of "any-snarf" program, as it will
fetch telnet sessions, FTP files, HTTP transfers (HTML, GIF, JPEG, ...), SMTP
emails, ... from the captured data inside network traffic logs. A html index
file is created that links to all the session details, including realtime
replay programs for telnet, rlogin, IRC, X11 and VNC sessions; and reports such
as image reports and HTTP GET/POST content reports. Chaosreader can also run in
standalone mode - where it invokes tcpdump or snoop (if they are available) to
create the log files and then processes them.
http://chaosreader.sourceforge.net/

* Tcpick

    Tcpick is a textmode sniffer libpcap-based that can track, reassemble and
reorder tcp streams. Tcpick is able to save the captured flows in different
files or displays them in the terminal, and so it is useful to sniff files that
are transmitted via ftp or http. It can display all the stream on the terminal,
when the connection is closed in different display modes like hexdump, hexdump
+ ascii, only printable characters, raw mode and so on. Available a color mode
too, helpful to read and understand better the output of the program. Actually
it can handle several interfaces, including ethernet cards and ppp. It is
useful to keep track of what users of a network are doing, and is usable with
textmode tools like grep, sed, awk. http://tcpick.sourceforge.net/

* Snort

    Snort is an open source network intrusion prevention and detection system
(IDS/IPS) developed by Sourcefire, now owned by Cisco. Combining the benefits of signature,
protocol and anomaly- based inspection, Snort is the most widely deployed
IDS/IPS technology worldwide. With millions of downloads and approximately
500,000 registered users, Snort has become the de facto standard for IPS.
http://www.snort.org/  Snort has the capability to write files to disk as they are captured
live, or from a pcap.

Other Projects<a name="others"></a>
-------------------------------------------

* FFT-FGN-C

    FFT-FGN-C is a program for synthesizing a type of self-similar process
known as fractional Gaussian noise. The program is fast but approximate.
Fractional Gaussian noise is only one type of self-similar process. When using
this program for synthesizing network traffic, you must keep in mind that it
may be that the traffic you seek is better modeled using one of the other
processes. The output of the program (perhaps transformed - see the
documentation) describes an arrival process, not an interarrival process. That
is, the output can be interpreted as a count of network arrivals during a
particular time interval; but if your application requires exact arrival times,
a separate mechanism is needed to transform the count into individual arrivals
(doing this is a research area).
http://ita.ee.lbl.gov/html/contrib/fft_fgn_c.html

* Usenix 93 paper on BPF

    The libpcap interface supports a filtering mechanism based on the
architecture in the BSD packet filter. BPF is described in the 1993 Winter
Usenix paper "The BSD Packet Filter: A New Architecture for User-level Packet
Capture".
> * The original is at: ftp://ftp.ee.lbl.gov/papers/bpf-usenix93.ps.Z
> * A copy (compressed postscript 144K):  http://www.tcpdump.org/papers
>   /bpf-usenix93.ps.Z
> * Gzip'ed postscript: http://www.tcpdump.org/papers/bpf-usenix93.ps.gz (100K)
> * For the Post-script impaired, here is some PDF:bpf-usenix93.pdf (135K)

* BPF for Ultrix

    A distribution of BPF for Ultrix 4.2, with both source code and binary
modules. http://www.tcpdump.org/other/bpfext42.tar.Z

* BPF+

    Exploiting Global Data-flow Optimization in a Generalized Packet Filter
Architecture By Andrew Begel, Steven McCanne, and Susan Graham, originally at:
http://www.cs.berkeley.edu/~abegel/sigcomm99/bpf+.ps

* DPF

    A paper presented at SIGCOMM '96 on an enhanced version of BPF.
http://www.pdos.lcs.mit.edu/~engler/dpf.html

* dnswasher

dnswasher takes an input file in PCAP format and writes out a PCAP file, 
while obfuscating end-user IP addresses. This is useful to share data with 
third parties while attempting to protect the privacy of your users.
https://doc.powerdns.com/md/manpages/dnswasher.1/

History
-----------

> * Update 2014-07-24: Traffic moniter tools under *nix (http://bit.do/J8qM)
> * Update 2013-01-01: Another similar list from Wireshark
>   (http://wiki.wireshark.org/Tools)
> * Update 2012-12-26: A similar collection of web version:
>   (http://bit.do/J8q4)
