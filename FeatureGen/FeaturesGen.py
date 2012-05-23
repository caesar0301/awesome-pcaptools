import os
import sys
import struct
import socket
import string
import time
import math
import pcap
import re

protocols={socket.IPPROTO_TCP:'tcp',
           socket.IPPROTO_UDP:'udp',
           socket.IPPROTO_ICMP:'icmp'}

def decodecHDLCHeader(s):
        d = {}
        d['address'], d['control'] = s[0], s[1]
        d['protocol'] = struct.unpack(">H", s[2:4])[0]
        d['data'] = s[4:]
        return d

def decodePPPHeader(s):

        d = {}
        if struct.unpack("BB", s[0:2]) == (0xff, 0x03):
                        # HDLC-framed
                d['protocol'] = struct.unpack(">H", s[2:4])[0]
                d['data'] = s[4:]
        else:
                        # No framing
                d['protocol'] = struct.unpack(">H", s[0:2])[0]
                d['data'] = s[2:]        
        return d


def decodeEtherHeader(s):
        """ Takes in a raw byte string and returns a dictionary
        with the following keys:
        destMAC
        srcMAC
        etherType
        data
        """
        d = {}
        d['destMAC'] = s[:6]
        d['srcMAC'] = s[6:12]
        d['etherType'] = struct.unpack(">H", s[12:14])[0]
        d['data'] = s[14:]
        d['len'] = len(d['data'])
        return d


def decodeIPHeader(s):
        """ Takes in a raw byte string of an IP packet
        and returns a dictionary with the following keys:

        version
        header_len
        tos
        total_len
        id
        flags
        fragment_offset
        ttl
        protocol
        checksum
        srcAddr
        dstAddr 
        options [MAYBE]
        data
        """
        # from pylibpcap...
        d={}
        d['version']=(ord(s[0]) & 0xf0) >> 4
        d['header_len']=ord(s[0]) & 0x0f
        d['tos']=ord(s[1])
        d['total_len']=socket.ntohs(struct.unpack('H',s[2:4])[0])
        d['id']=socket.ntohs(struct.unpack('H',s[4:6])[0])
        d['flags']=(ord(s[6]) & 0xe0) >> 5
        d['fragment_offset']=socket.ntohs(struct.unpack('H',s[6:8])[0] & 0x1f)
        d['ttl']=ord(s[8])
        d['protocol']=ord(s[9])
        d['checksum']=socket.ntohs(struct.unpack('H',s[10:12])[0])
        d['srcAddr']=pcap.ntoa(struct.unpack('i',s[12:16])[0])
        d['dstAddr']=pcap.ntoa(struct.unpack('i',s[16:20])[0])
        if d['header_len']>5:
                d['options']=s[20:4*(d['header_len']-5)]
        else:
                d['options']=None
        d['data'] = s[(4*(d['header_len'])):d['total_len']]
        d['len'] = len(d['data'])
        return d

def decodeTCPHeader(s):
        """ Takes in a raw byte string of an IP packet payload
        and returns a dictionary with the following keys:
        srcPort
        dstPort
        seqNum
        sckNum
        dataOffset
        flags
        window
        checksum
        urg
        options [MAYBE]
        data
        """
        d = {}
        d['srcPort'] = struct.unpack(">H", s[:2])[0]
        d['dstPort'] = struct.unpack(">H", s[2:4])[0]
        d['seqNum'] = struct.unpack(">I", s[4:8])[0] 
        d['ackNum'] = struct.unpack(">I", s[8:12])[0]
        d['dataOffset'] = (struct.unpack("B", s[12])[0] & 0xF0) >> 4
        d['flags'] = struct.unpack("B", s[13])[0] & 0x3F
        d['window'] = struct.unpack(">H", s[14:16])[0]
        d['checksum'] = struct.unpack(">H", s[16:18])[0]
        d['urg'] = struct.unpack(">H", s[18:20])[0]
        if d['dataOffset'] > 5:
                d['options'] = s[20:(4*d['dataOffset'])]
        else:
                d['options'] = None
        d['data'] = s[(4*d['dataOffset']):]
        d['len'] = len(d['data'])
        return d

def decodeUDPHeader(s):
        """ Takes in a raw byte string of an IP packet payload
        and returns a dictionary with the following keys:
            srcPort
            dstPort
            len
            checksum
            data
            """
        d = {}
        d['srcPort'] = struct.unpack(">H", s[:2])[0]
        d['dstPort'] = struct.unpack(">H", s[2:4])[0]
        d['len'] =     struct.unpack(">H", s[4:6])[0]
        d['checksum'] =struct.unpack('>H', s[6:8])[0]
        d['data'] = s[8:]
        d['len'] = len(d['data'])
        return d

class pcaputils:
        """ pcaputils(path) will open the capture file at path and 
        allow packet parsing with next() or auto() """
        def __init__(self, path):
                self.endian = None
                self.f = None
                self.path = None
                self.verMaj = None
                self.verMin = None
                self.tZone = None
                self.accuracy = None
                self.snaplen = None
                self.netType = None
                self.gHeaderFmt = "%sHHiIII"
                self.gHeaderLen = 20
                self.pHeaderFmt = "%sIIII"
                self.pHeaderLen = 16
                self.DLT_EN10MB = 1
                self.DLT_PPP = 9
                self.C_HDLC = 104
                self.RAW_IP = 101
                self.__open__(path)

        def __open__(self, path):
                self.path = path
                self.f = file(path, "rb")
                magicNumber = self.f.read(4)
                if magicNumber == "\xa1\xb2\xc3\xd4":
                        self.endian = ">"
                elif magicNumber == "\xd4\xc3\xb2\xa1":
                        self.endian = "<"
                else:
                        raise Exception("unknown magic number: %s" % repr(magicNumber))
                self.gHeaderFmt = self.gHeaderFmt % self.endian
                self.pHeaderFmt = self.pHeaderFmt % self.endian

                globalHeader = self.f.read(self.gHeaderLen)
                self.verMaj, self.verMin, self.tZone, self.accuracy, self.snaplen, self.netType = struct.unpack(self.gHeaderFmt, globalHeader)

                return True

        def next(self):
                """ trim the next packet off the capture and return it 
                    returns a tuple: (timestampSeconds, timestampUSeconds, packetData) """

                # TODO: return pythonic time format, incl timezones.

                packetHeader = self.f.read(self.pHeaderLen)
                while packetHeader:
                        tsSec, tsUSec, capLen, realLen = struct.unpack(self.pHeaderFmt, packetHeader)
                        packetData = self.f.read(capLen)
                        yield (tsSec, tsUSec, packetData)
                        packetHeader = self.f.read(self.pHeaderLen)

        def auto(self):
                """ will loop through the packet capture, parse the ethernet, 
                    ip, tcp and/or udp headers.

                    will compare the current packet to each subscription, 
                    and call the handler function on a match.

                    handler functions must take four arguments:
                       handler(timestampSeconds, timestampUSeconds, headerDict, fullPacketData)

                    subscriptions match on header values, using 
                    dictionaries named 'ether', 'ip', 'tcp' and/or 'udp' 
                    and the key values from the pcaputils.decode* functions. 
                """

                packetHeader = self.f.read(self.pHeaderLen)
                while packetHeader:
                        ip = None
                        ether = None
                        udp = None
                        tcp = None

                        tsSec, tsUSec, capLen, realLen = struct.unpack(self.pHeaderFmt, packetHeader)

                        packetData = self.f.read(capLen)

                        ipdata = None
                        if self.netType == self.DLT_EN10MB:
                                ether = decodeEtherHeader(packetData)
                                if ether['etherType'] == 0x0800:
                                        ipdata = ether['data']

                        elif self.netType == self.DLT_PPP:
                                ppp = decodePPPHeader(packetData)
                                if ppp['protocol'] == 0x0021:
                                        ipdata = ppp['data']

                        elif self.netType == self.C_HDLC:
                                chdlc = decodecHDLCHeader(packetData)
                                if chdlc['protocol'] == 0x0800:
                                        ipdata = chdlc['data']

                        elif self.netType == self.RAW_IP:
                                ipdata = packetData

                        else:
                                sys.exit("Unsupported link layer type: " + str(self.netType))

                        if ipdata is not None:

                                if len(ipdata) < 20:
                                        pass
                        #print >> sys.stderr, "IP packet too short, skipping (", len(ipdata), "bytes)"
                                else:
                                        ip = decodeIPHeader(ipdata)
                                        if ip['protocol'] == socket.IPPROTO_UDP:
                                                if len(ipdata) < 28:
                                                        pass
                        #print >> sys.stderr, "UDP packet too short, skipping (", len(ipdata), "bytes)"
                                                else:
                                                        udp= decodeUDPHeader(ip['data'])

                                        elif ip['protocol'] == socket.IPPROTO_TCP:
                                                if len(ipdata) < 40:
                                                        pass
                        #print >> sys.stderr, "TCP packet too short, skipping (", len(ipdata), "bytes)"
                                                else:
                                                        tcp = decodeTCPHeader(ip['data'])

                                        else:
                                                pass
                                #print >> sys.stderr, "Found non-TCP, non-UDP packet"

                        else:
                                print >> sys.stderr, "Found non-IP packet"

                        globals = {'ether': ether, 'ip': ip, 'tcp': tcp, 'udp': udp}

                        timestamp = float(tsSec) + (float(tsUSec) / 1e06)
                        getstats(timestamp,globals)

                        packetHeader = self.f.read(self.pHeaderLen)



# TCP flags
SYN = 0x02
FIN = 0X01
RST = 0x04
ACK = 0x10

# dictionary containing information on connections, idnexed by conenction identifier
cn = dict()

def getstats(timestamp,proto):

        conn_id = make_conn_id(proto)

        if not cn.has_key(conn_id):
                client_ip = proto['ip']['srcAddr']
                client_port = proto['tcp']['srcPort']
                server_ip = proto['ip']['dstAddr']
                server_port = proto['tcp']['dstPort']

                # these fields are used to keep track of the connection state
                cn[conn_id] = { 'start':timestamp,
                                'client_ip':client_ip,
                                'client_port':client_port,
                                'server_ip':server_ip,
                                'server_port':server_port,
                                'client_bytes_sent':0,
                                'server_bytes_sent':0,
                                'client_last_seq':None,
                                'server_last_seq':None,
                                'client_last_acked':None,
                                'server_last_acked':None,
                                'client_syn_sent':False,
                                'client_syn_acked':False,
                                'server_syn_sent':False,
                                'server_syn_acked':False,
                                'client_fin_sent':False,
                                'client_fin_acked':False,
                                'server_fin_sent':False,
                                'server_fin_acked':False,
                                'reset':False,
                                'endtime':0,
                                'packet_with_payload_num':0,
                                'duration':0,
                                'ff4_direction':'',
                                'ff4_size':list(),
                                'arrival_time_ab':list(),
                                'arrival_time_ba':list(),
                                'ether_len_ab':list(),
                                'ether_len_ba':list(),
                                'ip_len_ab':list(),
                                'ip_len_ba':list(),
                                'tcp_len_ab':list(),
                                'tcp_len_ba':list(),
                                'tcp_len_ab':list(),
                                'tcp_len_ba':list(),
                                'udp_len_ab':list(),
                                'udp_len_ba':list(),
                                'protocol':''
                                }

                #print >> sys.stderr, "Found new connection:", print_conn(cn[conn_id])

        if proto['ip']['protocol'] == socket.IPPROTO_UDP:
                cn[conn_id]['protocol'] = 'UDP'
        elif proto['ip']['protocol'] == socket.IPPROTO_TCP:
                cn[conn_id]['protocol'] = 'TCP'

        #if is a UDP packet:
        if proto['ip']['protocol'] == socket.IPPROTO_UDP:
                if proto['ip']['srcAddr'] == cn[conn_id]['client_ip']:
                        cn[conn_id]['ether_len_ab'].append(proto['ether']['len'])
                        cn[conn_id]['ip_len_ab'].append(proto['ip']['len'])
                        cn[conn_id]['arrival_time_ab'].append(timestamp)
                        cn[conn_id]['udp_len_ab'].append(proto['udp']['len'])
                else:
                        cn[conn_id]['ether_len_ba'].append(proto['ether']['len'])
                        cn[conn_id]['ip_len_ba'].append(proto['ip']['len'])
                        cn[conn_id]['arrival_time_ba'].append(timestamp)
                        cn[conn_id]['udp_len_ba'].append(proto['udp']['len'])
                return

        # if the connetion had already been closed, this packet should be ignored
        if wasClosed(cn[conn_id]):
                #print >> sys.stderr, "ignoring packet from closed connection (", print_conn(cn[conn_id]), ")"
                return

        # handle SYN packets
        if proto['tcp']['flags'] & SYN:                   
                if proto['ip']['srcAddr'] == cn[conn_id]['client_ip']:
                        if cn[conn_id]['client_syn_sent']:
                                #duplucat syn
                                pass
                        cn[conn_id]['client_syn_sent'] = True
                        cn[conn_id]['client_last_seq'] = proto['tcp']['seqNum']

                else:
                        if cn[conn_id]['server_syn_sent']:
        # duplucat syn
                                pass
                        cn[conn_id]['server_syn_sent'] = True
                        cn[conn_id]['server_last_seq'] = proto['tcp']['seqNum']

        # handle ACK packets
        if proto['tcp']['flags'] & ACK:

        # connection wasn't open yet, this must be an ACK for a SYN
                if not wasOpened(cn[conn_id]):
                        if proto['ip']['srcAddr'] == cn[conn_id]['client_ip'] and cn[conn_id]['server_syn_sent']:
                                if proto['tcp']['ackNum'] == cn[conn_id]['server_last_seq'] + 1:
                                        cn[conn_id]['server_syn_acked'] = True
                                else:
        # must have missed a SYN packet, ignore
                                        pass
                #sys.exit("SYN sequence number mismatch in connection " + print_conn_id(conn_id) + "\n" + print_conn(cn[conn_id]) + "\n" + print_packet(proto))

                        elif proto['ip']['dstAddr'] == cn[conn_id]['client_ip'] and cn[conn_id]['client_syn_sent']:
                                if proto['tcp']['ackNum'] == cn[conn_id]['client_last_seq'] + 1:
                                        cn[conn_id]['client_syn_acked'] = True
                                else:
        # must have missed a SYN packet, ignore
                                        pass
                        #sys.exit("SYN sequence number mismatch in connection " + print_conn_id(conn_id) + "\n" + print_conn(cn[conn_id]) + "\n" + print_packet(proto))


                else:
        # if a->b
                        if proto['ip']['srcAddr'] == cn[conn_id]['client_ip']:
                                cn[conn_id]['ether_len_ab'].append(proto['ether']['len'])
                                cn[conn_id]['ip_len_ab'].append(proto['ip']['len'])
                                cn[conn_id]['arrival_time_ab'].append(timestamp)
        # increase the last acked field according to what we saw in the packet
        # the following test is necessary because sometimes TCP receiver "pre ack" by
        # acknowledging packets that haven't been sent yet to inflate the cognestion window
        # we want to avoid this
                                if proto['tcp']['ackNum'] > cn[conn_id]['server_last_seq'] + 1:
        # ignore pre-acking 
                                        proto['tcp']['ackNum'] = cn[conn_id]['server_last_seq'] + 1

        # update lasta acked field for the connection endpoint
                                cn[conn_id]['server_last_acked'] = max(proto['tcp']['ackNum'], cn[conn_id]['server_last_acked'])
        # handle ACK for FIN packets
                                if cn[conn_id]['server_fin_sent'] and cn[conn_id]['server_last_seq'] + 1 == proto['tcp']['ackNum']:
                                        cn[conn_id]['server_fin_acked'] = True

                        else:
                                cn[conn_id]['ether_len_ba'].append(proto['ether']['len'])
                                cn[conn_id]['ip_len_ba'].append(proto['ip']['len'])
                                cn[conn_id]['arrival_time_ba'].append(timestamp)
        # same as above, symmetrical for the other connectione end
                                if proto['tcp']['ackNum'] > cn[conn_id]['client_last_seq'] + 1:
        # ignore pre-acking 
                                        proto['tcp']['ackNum'] = cn[conn_id]['client_last_seq'] + 1

                                cn[conn_id]['client_last_acked'] = max(proto['tcp']['ackNum'], cn[conn_id]['client_last_acked'])
                                if cn[conn_id]['client_fin_sent'] and cn[conn_id]['client_last_seq'] + 1 == proto['tcp']['ackNum']:
                                        cn[conn_id]['client_fin_acked'] = True


        # handle packets with payload
        if len(proto['tcp']['data']) > 0:
        # if connection wasn't opened, ignore
                if not wasOpened(cn[conn_id]):
        #            print >> sys.stderr, "ignoring data packet for connection for which we did not see a SYN exchange! (", print_conn_id(conn_id), print_conn(cn[conn_id]), print_packet(proto, data), ")"
        #print >> sys.stderr, "ignoring data packet for connection for which we did not see a SYN exchange!"
                        return

                cn[conn_id]['packet_with_payload_num'] += 1

                if proto['ip']['srcAddr'] == cn[conn_id]['client_ip']:
                        if proto['tcp']['seqNum'] > cn[conn_id]['client_last_seq']:
                                cn[conn_id]['tcp_len_ab'].append(proto['tcp']['len'])
        # packet is not a retransmission
        # update the sequence number field            
                                cn[conn_id]['client_last_seq'] += len(proto['tcp']['data'])
                                cn[conn_id]['client_bytes_sent'] += len(proto['tcp']['data'])
        # ff4_size and direction		
                                if len(cn[conn_id]['ff4_direction'])<4:
                                        cn[conn_id]['ff4_direction']+='1'
                                        cn[conn_id]['ff4_size'].append(proto['tcp']['len'])
                        else:
        # retransmitted segment, ignore
                                pass
                else:
                        if proto['tcp']['seqNum'] > cn[conn_id]['server_last_seq']:
                                cn[conn_id]['tcp_len_ba'].append(proto['tcp']['len'])
        # new data
                                cn[conn_id]['server_last_seq'] += len(proto['tcp']['data'])
                                cn[conn_id]['server_bytes_sent'] += len(proto['tcp']['data'])
        # ff4_size and direction		
                                if len(cn[conn_id]['ff4_direction'])<4:
                                        cn[conn_id]['ff4_direction']+='0'
                                        cn[conn_id]['ff4_size'].append(proto['tcp']['len'])
                        else:
        # retransmitted segment
                                pass

        # handle FIN packets
        if wasOpened(cn[conn_id]):
                if proto['tcp']['flags'] & FIN:                
                        if proto['ip']['srcAddr'] == cn[conn_id]['client_ip'] and not cn[conn_id]['client_fin_sent']:
                                cn[conn_id]['client_fin_sent'] = True
                                cn[conn_id]['client_last_seq'] += 1        
                        else:
                                cn[conn_id]['server_fin_sent'] = True
                                cn[conn_id]['server_last_seq'] += 1

        # handle RST packets
        if proto['tcp']['flags'] & RST:
                cn[conn_id]['reset'] = True

        # judge whether the flow has ended

        if wasClosed(cn[conn_id]):
                cn[conn_id]['endtime'] = timestamp
                cn[conn_id]['duration'] = cn[conn_id]['endtime'] - cn[conn_id]['start']

def print_conn(conn):
        return "%s:%s <-> %s:%s" % (conn['client_ip'], conn['client_port'], conn['server_ip'], conn['server_port'])

def print_conn_single_word(conn):
        return "client-%s-%s-server-%s-%s" % (conn['client_ip'], conn['client_port'], conn['server_ip'], conn['server_port'])

def wasClosed(conn):
        """check if a connection was closed (either by FIN exchange, or with RST)"""
        return (conn['client_fin_sent'] and conn['server_fin_sent'] and conn['client_fin_acked'] and conn['server_fin_acked']) or conn['reset']

def wasOpened(conn):
        """check if a connection was opened with SYN exchange"""
        return conn['client_syn_sent'] and conn['server_syn_sent'] and conn['client_syn_acked'] and conn['server_syn_acked']

def make_conn_id(proto):
        """build a unique string identifier for the connection that is used to uniquely identify each connection in the dictionaries"""

        srcip = proto['ip']['srcAddr']
        srcport = proto['tcp']['srcPort']
        dstip = proto['ip']['dstAddr']
        dstport = proto['tcp']['dstPort']

        if (srcip < dstip):
                return srcip + ":" + str(srcport) + ":" + dstip + ":" + str(dstport)
        else:
                return dstip + ":" + str(dstport) + ":" + srcip + ":" + str(srcport)

def  median(d):
        d.sort()
        length = len(d)
        if (length % 2) == 0:
                return d[length/2 -1 ] /2 +d[length/2] /2
        else:
                return d[length/2]

def mean(l):
        return sum(l)/len(l)

def variance (l):
	tmp = mean(l)
	return sum([(i - tmp) ** 2 for i in l]) / len(l)
	
def GetIAT(t):
	IAT = list()
	if len(t) == 0:
		return IAT
	else:
		t.sort()
		for i in range(1,len(t)-1):
			IAT.append(t[i]-t[i-1])
		return IAT	

def printstats (fstats,conns):
	
	fstats.write(str(conns['protocol']) + ' ' + str(conns['client_ip']) + ' ' + str(conns['client_port']) + ' ' + str(conns['server_ip']) + ' ' + str(conns['server_port']) + ' ')
	
	arrival_time = list()
	arrival_time.extend(conns['arrival_time_ab'])
	arrival_time.extend(conns['arrival_time_ba'])
	IAT = GetIAT(arrival_time)
	if len(IAT) == 0:
		fstats.write('0 0 0 0 0 ')
	else:
		fstats.write(str(min(IAT)) + ' ' + str(max(IAT)) + ' ' + str(mean(IAT))+ ' ' + str(median(IAT)) + ' '+ str(variance(IAT))+ ' ')
		
	Ether = list()
	Ether.extend(conns['ether_len_ab'])
	Ether.extend(conns['ether_len_ab'])
	if len(Ether) == 0:
		fstats.write('0 0 0 0 0 ')
	else:
		fstats.write(str(min(Ether)) + ' ' + str(max(Ether)) + ' ' + str(mean(Ether))+ ' ' + str(median(Ether)) + ' '+ str(variance(Ether))+ ' ')
	
	IP = list()
	IP.extend(conns['ip_len_ab'])
	IP.extend(conns['ip_len_ba'])
	if len(IP) == 0:
		fstats.write('0 0 0 0 0 ')
	else:
		fstats.write(str(min(IP)) + ' ' + str(max(IP)) + ' ' + str(mean(IP))+ ' ' + str(median(IP)) + ' '+ str(variance(IP))+ ' ')

	TCP = list()
	TCP.extend(conns['tcp_len_ab'])
	TCP.extend(conns['tcp_len_ba'])
	if len(TCP) == 0:
		fstats.write('0 0 0 0 0 ')
	else:
		fstats.write(str(min(TCP)) + ' ' + str(max(TCP)) + ' ' + str(mean(TCP))+ ' ' + str(median(TCP)) + ' '+ str(variance(TCP))+ ' ')
	
	UDP = list()
	UDP.extend(conns['udp_len_ab'])
	UDP.extend(conns['udp_len_ba'])
	if len(UDP) == 0:
		fstats.write('0 0 0 0 0 ')
	else:
		fstats.write(str(min(UDP)) + ' ' + str(max(UDP)) + ' ' + str(mean(UDP))+ ' ' + str(median(UDP)) + ' '+ str(variance(UDP))+ ' ')
	
	
	if len(conns['ff4_direction']) > 0:
		fstats.write(conns['ff4_direction'] + ' ' )
	else:
		fstats.write('NULL ')
	if len(conns['ff4_size'] )< 4:
		conns['ff4_size'][len(conns['ff4_size']):4] =[0]*(4-len(conns['ff4_size'] ))
	for tmp in conns['ff4_size']:
		fstats.write(str(tmp)+' ')
    # print ether_len_stats	
	if len(conns['ether_len_ab']) > 0 :
		fstats.write(str(min(conns['ether_len_ab'])) + ' ' +str(max(conns['ether_len_ab'])) + ' ' +str(mean(conns['ether_len_ab'])) + ' ' + str(median(conns['ether_len_ab'])) + ' ' + str(variance(conns['ether_len_ab'])) + ' ')
	else :
		fstats.write('0 0 0 0 ')
	if len(conns['ether_len_ba']) > 0 :
		fstats.write(str(min(conns['ether_len_ba'])) + ' ' +str(max(conns['ether_len_ba'])) + ' ' +str(mean(conns['ether_len_ba'])) + ' ' + str(median(conns['ether_len_ba'])) + ' ' + str(variance(conns['ether_len_ba'])) + ' ')
	else :
		fstats.write('0 0 0 0 ')
    # print ip_len_stats
	if len(conns['ip_len_ab']) > 0 :
		fstats.write(str(min(conns['ip_len_ab'])) + ' ' +str(max(conns['ip_len_ab'])) + ' ' +str(mean(conns['ip_len_ab'])) + ' ' + str(median(conns['ip_len_ab'])) + ' ' + str(variance(conns['ip_len_ab'])) + ' ')
	else :
		fstats.write('0 0 0 0 ')
	if len(conns['ip_len_ba']) > 0 :
		fstats.write(str(min(conns['ip_len_ba'])) + ' ' +str(max(conns['ip_len_ba'])) + ' ' +str(mean(conns['ip_len_ba'])) + ' ' + str(median(conns['ip_len_ba'])) + ' ' + str(variance(conns['ip_len_ba'])) + ' ')
	else :
		fstats.write('0 0 0 0 ')	
    # print udp/tcp_len_stats	
	if conns['protocol'] == 'TCP':
		if len(conns['tcp_len_ab']) > 0 :
			fstats.write(str(min(conns['tcp_len_ab'])) + ' ' +str(max(conns['tcp_len_ab'])) + ' ' +str(mean(conns['tcp_len_ab'])) + ' ' + str(median(conns['tcp_len_ab'])) + ' ' + str(variance(conns['tcp_len_ab'])) + ' ')
		else :
			fstats.write('0 0 0 0 ')
		if len(conns['tcp_len_ba']) > 0 :
			fstats.write(str(min(conns['tcp_len_ba'])) + ' ' +str(max(conns['tcp_len_ba'])) + ' ' +str(mean(conns['tcp_len_ba'])) + ' ' + str(median(conns['tcp_len_ba'])) + ' ' + str(variance(conns['tcp_len_ba'])) + ' ')
		else :
			fstats.write('0 0 0 0 ')
		fstats.write('NULL NULL NULL NULL NULL NULL NULL NULL ')
	else:
		fstats.write('NULL NULL NULL NULL NULL NULL NULL NULL ')
		if len(conns['udp_len_ab']) > 0 :
			fstats.write(str(min(conns['udp_len_ab'])) + ' ' +str(max(conns['udp_len_ab'])) + ' ' +str(mean(conns['udp_len_ab'])) + ' ' + str(median(conns['udp_len_ab'])) + ' ' + str(variance(conns['udp_len_ab'])) + ' ')
		else :
			fstats.write('0 0 0 0 ')
		if len(conns['udp_len_ba']) > 0 :
			fstats.write(str(min(conns['udp_len_ba'])) + ' ' +str(max(conns['udp_len_ba'])) + ' ' +str(mean(conns['udp_len_ba'])) + ' ' + str(median(conns['udp_len_ba'])) + ' ' + str(variance(conns['udp_len_ba'])) + ' ')
		else :
			fstats.write('0 0 0 0 ')

    # print arrival times
	IAT_ab = GetIAT(conns['arrival_time_ab'])
	IAT_ba = GetIAT(conns['arrival_time_ba'])
	if len(IAT_ab) == 0:
		fstats.write('0 0 ')
	else:
		fstats.write(str(mean(IAT_ab)) + ' ' + str(variance(IAT_ab)) + ' ')
	if len(IAT_ba) == 0:
		fstats.write('0 0 ')
	else:
		fstats.write(str(mean(IAT_ba)) + ' ' + str(variance(IAT_ba)) + ' ')


def main(args):

	if len(args) == 1:
		print "usage : getstats.py <filelist>"

	filelist = open(args[1],'r')

	# file for print stats
	fstats = open('Features_all','wb')

	allpcap_files = list()
	tmp = filelist.readline()
	while tmp:
		allpcap_files.append(tmp.rstrip('\n'))
		tmp = filelist.readline()

# handle all files
	for pcap_file in allpcap_files:
		pcap = pcaputils(pcap_file)
		pcap.auto()
		
		for conns in cn.values():
			printstats(fstats,conns)
		cn.clear()
		
		
		tcptrace_char = os.popen('tcptrace -l -r -o1 -n '+pcap_file ).read()
		tcptrace_start_found = 0
		tcptrace_char = tcptrace_char.split('\n')
		for line in tcptrace_char:
			if not tcptrace_start_found:
				if re.search("a->b",line):
					tcptrace_start_found += 1
			else:
				m = re.findall('^\s+[^:]*:\s+(\S+)[^:]*:\s+(\S+).*',line)
				if len(m):
					for statsss in m:
						fstats.write(str(statsss[0])+' '+str(statsss[1])+' ')
		
		fstats.write('\n')

	fstats.close()

if __name__ == "__main__":    
	sys.exit(main(sys.argv))	

