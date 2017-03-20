#! /usr/bin/env python2.7

##
## Copyright (C) 2012,  Netronome Systems, Inc.  All rights reserved.
##

"""
TODO Ideas:
+ Add hostname to MAC address options and try and retrieve MAC address
  for hostname.
+ Option for using a <blaster>.blast file with flows defined
+ Add support for multiple MPLS headers
"""

"""A Python script to create and send packets out an interface
   or save the packets to a file"""

# Stop scapy warnings about v6 default routes
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import sys, os, string

from scapy.all import *
from optparse import *

# MPLS Packet
class MPLS(Packet):
   name = "MPLS"
   fields_desc =  [ BitField("label", 3, 20),
                    BitField("cos", 0, 3),
                    BitField("s", 1, 1),
                    ByteField("ttl", 0)  ]

bind_layers(Ether, MPLS, type=0x8847)

class MakePackets():
    """Make packets

    """

    def __init__(self, src_mac, src_ip, src_port,
                 dst_mac, dst_ip, dst_port, proto, payload_size=16, iter=1,
                 cfg_vlan=None, cfg_gre=None, cfg_mpls=None):
        """
        Initialise the system object.

        @src_mac:       Source Mac address <Mac> or <From Mac>-<To Mac>
        @src_ip:        Source IP address <IP> or <From IP>-<To IP>
        @src_port:      Source Port address <Port> or <From Port>-<To Port>
        @dst_mac:       Destination Mac address <Mac> or <From Mac>-<To Mac>
        @dst_ip:        Destination IP address <IP> or <From IP>-<To IP>
        @dst_port:      Destination Port address <Port> or <From Port>-<To Port>
        @proto:         Protocol Number <Proto> or <From proto>-<To Proto>
        @payload_size:  Payload size for data in generated packet; default:16
        @iter:          Number of iterations of gen_pkts(), when generating packets
                        default:1
        @cfg_vlan:      Vlan number and priority; A string containing
                        <vlan number>,<PCP>,<DEI. default: None
        @cfg_gre:       GRE Tunnel Confifuration; A string containing 
                        <sMAC>,<dMAC>,<sIP>,<dIP>,<key>  if <key> is 0,
                        no key will be used
                        default: None; No GRE header added to packet
        @cfg_mpls:      MPLS Header; A string containing 
                        <sMAC>,<dMAC>,<MPLS Label>,<MPLS COS>,<MPLS TTL>
                        default: None, No MPLS header added to packet
        """

        self.src_mac      = src_mac
        self.src_ip       = src_ip
        self.src_port     = src_port
        self.dst_mac      = dst_mac
        self.dst_ip       = dst_ip
        self.dst_port     = dst_port
        self.proto        = proto
        self.payload_size = payload_size
        self.iter         = iter
        self.cfg_vlan     = cfg_vlan
        self.cfg_gre      = cfg_gre
        self.cfg_mpls     = cfg_mpls

    def gen_pkts(self):

        s_src_mac, e_src_mac = self._validate_mac(self.src_mac)
        n_src_mac = e_src_mac - s_src_mac + 1

        s_dst_mac, e_dst_mac = self._validate_mac(self.dst_mac)
        n_dst_mac = e_dst_mac - s_dst_mac + 1

        s_src_ip, e_src_ip = self._validate_ip(self.src_ip)
        n_src_ip = e_src_ip - s_src_ip + 1

        s_dst_ip, e_dst_ip = self._validate_ip(self.dst_ip)
        n_dst_ip = e_dst_ip - s_dst_ip + 1

        s_src_port, e_src_port = self._validate_port(self.src_port)
        n_src_port = e_src_port - s_src_port + 1

        s_dst_port, e_dst_port = self._validate_port(self.dst_port)
        n_dst_port = e_dst_port - s_dst_port + 1

        s_proto, e_proto = self._validate_proto(self.proto)
        n_proto = e_proto - s_proto + 1

        # Calculate the number of packets to generate
        gen_pkt_cnt = n_src_ip * n_dst_ip * n_src_port * n_dst_port * n_proto * n_src_mac * n_dst_mac

        print "Generating %d Packets" % (gen_pkt_cnt * self.iter)

        pkts = []
        for i in xrange(self.iter):
            for src_mac in range(s_src_mac, e_src_mac+1):
                for dst_mac in range(s_dst_mac, e_dst_mac+1):
                    for proto in range(s_proto, e_proto+1):
                        for dst_port in range(s_dst_port, e_dst_port+1):
                            for src_port in range(s_src_port, e_src_port+1):
                                for src_ip in range(s_src_ip, e_src_ip+1):
                                    for dst_ip in range(s_dst_ip, e_dst_ip+1):
                                        mac_src = ':'.join(s.encode('hex') for s
                                                  in format(src_mac, "012x").\
                                                  decode('hex'))
                                        mac_dst = ':'.join(s.encode('hex') for s
                                                  in format(dst_mac, "012x").\
                                                  decode('hex'))
                                        print "src:%s.%s:%d dst:%s.%s:%d proto:%d" % \
                                              (mac_src, self._numToDottedIPv4(src_ip),
                                               src_port,
                                               mac_dst, self._numToDottedIPv4(dst_ip),
                                               dst_port,
                                               proto)

                                        payload = ''.join([chr(x & 0xff) for x in xrange(self.payload_size)])

                                        # XXX Add other proto support when needed
                                        if proto == 6: # TCP
                                            pkt = IP(src=self.\
                                                         _numToDottedIPv4(src_ip),
                                                     dst=self.\
                                                         _numToDottedIPv4(dst_ip),
                                                         proto=proto)/\
                                                  TCP(sport=src_port,
                                                      dport=dst_port, flags="S")/\
                                                  payload
                                        elif proto == 17: # UDP
                                            pkt = IP(src=self.\
                                                         _numToDottedIPv4(src_ip),
                                                     dst=self.\
                                                         _numToDottedIPv4(dst_ip),
                                                         proto=proto)/\
                                                  UDP(sport=src_port,
                                                      dport=dst_port)/\
                                                  payload
                                        elif proto == 1: # ICMP
                                            pkt = IP(src=self.\
                                                         _numToDottedIPv4(src_ip),
                                                     dst=self.\
                                                         _numToDottedIPv4(dst_ip),
                                                         proto=proto)/\
                                                  ICMP()

                                        if not self.cfg_vlan == None:
                                            vlan_num = int(self.cfg_vlan.split(",")[0])
                                            vlan_prio = int(self.cfg_vlan.split(",")[1])
                                            vlan_dei = int(self.cfg_vlan.split(",")[2])
                                            pkt = Dot1Q(id=vlan_dei, prio=vlan_prio, vlan=vlan_num)/pkt

                                        # Add MPLS header
                                        if not self.cfg_mpls == None:
                                            sMAC      = options.cfg_mpls.split(",")[0]
                                            dMAC      = options.cfg_mpls.split(",")[1]
                                            mplsLabel = int(options.cfg_mpls.split(",")[2])
                                            mplsCos   = int(options.cfg_mpls.split(",")[3])
                                            mplsTTL   = int(options.cfg_mpls.split(",")[4])

                                            # Generare a single MPLS packet header
                                            pkt = Ether(src=sMAC,
                                                        dst=dMAC)/\
                                                  MPLS(label=mplsLabel,cos=mplsCos,
                                                       s=1,ttl=mplsTTL)/pkt
                                        else:
                                            pkt = Ether(src=mac_src, dst=mac_dst)/pkt

                                        # Add GRE header
                                        if not self.cfg_gre == None:
                                            sMAC = options.cfg_gre.split(",")[0]
                                            dMAC = options.cfg_gre.split(",")[1]
                                            sIP  = options.cfg_gre.split(",")[2]
                                            dIP  = options.cfg_gre.split(",")[3]
                                            key  = options.cfg_gre.split(",")[4]
                                            if int(key) == 0:
                                                keyPresent = 0
                                            else:
                                                keyPresent = 1

                                            pkt = Ether(src=sMAC,
                                                        dst=dMAC)/\
                                                  IP(src=sIP, dst=dIP)/\
                                                  GRE(proto=0x6558,
                                                      key_present=keyPresent,
                                                      key=int(key))/pkt

                                        pkts.append(pkt)

        return pkts

    def save(self, fname):
        """Save packets to a file
        @fname: Filename to save packets to
        """
        wrpcap(fname, pkts)

    def _validate_mac(self, nums):
        # 00:11:22:33:44:55-66:77:88:99:00:11
        start = None
        end   = None

        n_start = 0
        n_end = 0

        if nums.find('-') != -1:
            start = nums.split('-')[0]
            end   = nums.split('-')[1]
        else:
            start = nums
            end   = start

        # Pad zero's to mac string address, then remove the ':'
        start = ":".join([i.zfill(2) for i in start.split(":")]).lower().replace(":", "")
        end   = ":".join([i.zfill(2) for i in end.split(":")]).lower().replace(":", "")

        # Convert the numbers to decimal
        # (Handles numbers prefixed with '0x')
        if start:
            n_start = int("0x%s" % start,0)

        if end:
            n_end = int("0x%s" % end,0)

        if n_start != 0:
            num = 1
        else:
            num = 0

        # Check end > start if end !=0
        # Validate end > start if end != 0
        if (n_end !=0) and (n_end > n_start):
            num = n_end - n_start + 1

        #print format(n_start, "012x")
        #print n_end
        # Convert MAC address to MAC string (i.e. 11:22:33:44:55:66)
        #print ':'.join(s.encode('hex') for s in format(n_start, "012x").decode('hex'))

        return n_start, n_end

    def _validate_ip(self, nums):
        # 192.123.12.2-200.3.4.5
        start = None
        end   = None

        n_start = 0
        n_end = 0

        if nums.find('-') != -1:
            start = nums.split('-')[0]
            end   = nums.split('-')[1]
        else:
            start = nums
            end   = start

        # Convert the numbers to decimal
        # (Handles numbers prefixed with '0x')
        if start:
            n_start = self._dottedIPv4ToNum(start)

        if end:
            n_end = self._dottedIPv4ToNum(end)

        if n_start != 0:
            num = 1
        else:
            num = 0

        # Check end > start if end !=0
        # Validate end > start if end != 0
        if (n_end !=0) and (n_end > n_start):
            num = n_end - n_start + 1

        return n_start, n_end

    def _validate_port(self, port):
        return self._validate_2_numbers(port)

    def _validate_proto(self, proto):
        return self._validate_2_numbers(proto)

    def _dottedIPv4ToNum(self, s):
        """convert decimal dotted IPv4 string to long integer"""
        return reduce(lambda a,b: a<<8 | b, map(int, s.split(".")))

    def _numToDottedIPv4(self, ip):
        """convert long int to dotted IPv4 string"""
        return ".".join(map(lambda n: str(ip>>n & 0xFF), [24,16,8,0]))

    def _validate_2_numbers(self, nums):
        # 10-20

        start = None
        end   = None

        n_start = 0
        n_end = 0

        if nums.find('-') != -1:
            start = nums.split('-')[0]
            end   = nums.split('-')[1]
        else:
            start = nums
            end   = nums

        # Convert the numbers to decimal
        # (Handles numbers prefixed with '0x')
        if start:
            n_start = int(start,0)

        if end:
            n_end = int(end,0)

        if n_start != 0:
            num = 1
        else:
            num = 0

        # Check end > start if end !=0
        # Validate end > start if end != 0
        if (n_end !=0) and (n_end > n_start):
            num = n_end - n_start + 1

        return n_start, n_end

# ---------------------------------------------------------------------------------
if __name__ == '__main__':

    filename = None
    verbose = True

    option_list = [
        make_option("-f", "--filename",
                    action="store", type="string", dest="filename",
                    default=None,
                    help="Filename to save packet(s) (NB: Will not send packet out on interface)"),
        #make_option("-v", "--verbose",
        #            action="store_true", dest="verbose",
        #            default=False),
        #make_option("-q", "--quiet",
        #            action="store_true", dest="quiet",
        #            default=False),
        make_option("-m", "--dl-src",
                    action="store", dest="dl_src",
                    default="11:22:33:44:55:66",
                    help="Source MAC Address (default:11:22:33:44:55:66) <From>-<To> for multiple packet generation"),
        make_option("-n", "--dl-dst",
                    action="store", dest="dl_dst",
                    default="22:33:44:55:66:77",
                    help="Destination MAC Address (default:22:33:44:55:66:77) <From>-<To> for multiple packet generation"),
        make_option("-x", "--nw-src",
                    action="store", dest="nw_src",
                    default="10.0.0.1",
                    help="Source IP Address (default:10.0.0.1) <From>-<To> for multiple packet generation"),
        make_option("-r", "--nw-dst",
                    action="store", dest="nw_dst",
                    default="10.0.0.100",
                    help="Destination IP Address (default:10.0.0.100) <From>-<To> for multiple packet generation"),
        make_option("-s", "--tp-src",
                    action="store", dest="tp_src",
                    default="3000",
                    help="Source Port Number (default:3000) <From>-<To> for multiple packet generation"),
        make_option("-d", "--tp-dst",
                    action="store", dest="tp_dst",
                    default="4000",
                    help="Destination Port Number (default:4000) <From>-<To> for multiple packet generation"),
        make_option("-p", "--proto",
                    action="store", dest="proto",
                    default="17",
                    help="Prototype (default:17) <From>-<To>\nOnly ICMP (1), UDP (17) and TCP (6) really supported"),
        make_option("-G", "--gre",
                    action="store", dest="cfg_gre",
                    default=None,
                    help="Add GRE header <sMAC>,<dMAC>,<sIP>,<dIP>,<key>\nif <key> is 0, no key will be used"),
        make_option("-M", "--mpls",
                    action="store", dest="cfg_mpls",
                    default=None,
                    help="Add MPLS header <sMAC>,<dMAC>,<MPLS Label>,<MPLS COS>,<MPLS TTL>"),
        make_option("-l", "--vlan",
                    action="store", dest="cfg_vlan",
                    default=None,
                    help="Add a VLAN tag"),
        make_option("-i", "--interface",
                    action="store", dest="interface",
                    default="eth0",
                    help="Interface to send packet"
                    ),
        make_option("-P", "--payload",
                    action="store", dest="payload",
                    default="16",
                    help="Payload size (default:16 bytes)"),
        make_option("-I", "--iter",
                    action="store", dest="iter",
                    default="1",
                    help="Number of 'generated packets' sets to create (default:1)"),
        ]

    usage = "usage: %prog [options]\n"
    usage += "A Packet generator tool to generate packets for sending\n"
    usage += "out on a physical interface or save to a pcap file."

    parser = OptionParser(usage, option_list=option_list)

    (options, _) = parser.parse_args()

    # Configure the interface to send packet from
    conf.iface = options.interface

    # if not root...kick out
    if not os.geteuid()==0:
        sys.exit("\nOnly root can run this script\n")

    pkts = []
    #p = MakePackets("0:1:2:3:4:5", "10.0.1.1-10.0.1.10",  "6543",
    #                "0:1:2:3:4:7", "10.2.2.2", "80", "7")
    p = MakePackets(options.dl_src, options.nw_src, options.tp_src,
                    options.dl_dst, options.nw_dst, options.tp_dst,
                    options.proto, int(options.payload), iter=int(options.iter),
                    cfg_vlan=options.cfg_vlan,
                    cfg_gre=options.cfg_gre,
                    cfg_mpls=options.cfg_mpls)

    pkts = p.gen_pkts()

    if options.filename != None:
        p.save(options.filename)
    else:
        # Send the packet out of the interface
        sendp(pkts)

    #for pkt in pkts:
    #    pkt.show2()
