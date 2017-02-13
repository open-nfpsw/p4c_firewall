from scapy.all import *
import argparse
import time
import threading
from threading import Event

from RTEInterface import RTEInterface

THRIFT_API_LOCK = threading.Lock()

class TimerThread(threading.Thread):
    def __init__(self, event, rule_timeout, internal_ports):
        threading.Thread.__init__(self)
        self.stopped = event
        self.rule_timeout = rule_timeout
        self.internal_ports = internal_ports

    def run(self):
        while not self.stopped.wait(self.rule_timeout):
            #print("Timeout poll")

            with THRIFT_API_LOCK:
                counterList = RTEInterface.Counters.ListP4Counters()
                tableId = counterList[0].tableid # Only have 1 table with counters in this example (Hardcoded 0)
                ruleList = RTEInterface.Tables.ListRules(tableId)
                counterValueList = []

                for i in range(self.internal_ports + 2,len(ruleList)):
                    # #print(ruleList[i].rule_name)
                    try:
                        counterValueList.append(RTEInterface.Counters.GetP4Counter(counterList[0])[i])
                        if RTEInterface.Counters.GetP4Counter(counterList[0])[i] == 0:
                            #print("Deleting rule: " + ruleList[i].rule_name)
                            RTEInterface.Tables.DeleteRule(tableId, ruleList[i].rule_name, False, "{}", "{}")
                            # time.sleep(0.01)
                    except:
                        print("Error trying to append counter value")

                #print(counterValueList)
                RTEInterface.Counters.ClearAllP4Counters()

class FuncThread(threading.Thread):
    def __init__(self, target, *args):
        self._target = target
        self._args = args
        threading.Thread.__init__(self)

    def run(self):
        self._target(*self._args)


class PacketProcessor(object):
    def __init__(self, router_ext_ip, cur_tcp_port, ext_port, controller_port, 
                 controller_port_rules, device_number,ruleNum):
        self.router_ext_ip = router_ext_ip
        self.cur_tcp_port = cur_tcp_port
        self.ext_port = ext_port
        self.controller_port = controller_port
        self.controller_port_rules = controller_port_rules
        self.device_number = device_number
        self.ruleNum = ruleNum
        
        self.processedList = {}

    def __call__(self, x):
        t1 = FuncThread(self.processPacket, x)
        t1.daemon = True
        t1.start()

    def natAndSend(self,packet,port):
        # NAT for first packet - This removes the need to dynamically add the 3rd rule (Controller Rule)
        # A static rule in P4 now sends packets received back form the controller out the external port.
        packet[IP].src = self.router_ext_ip
        packet[TCP].sport = port

        # Recalculate checksum Scapy way?
        del packet[IP].chksum
        del packet[TCP].chksum
        packet = packet.__class__(str(packet))

        # packet already processed so don't process again - resubmit so reason won't be valid anymore
        new_p_str = '\x00' * 6 + str(packet)

        #print "threading.active_count " + str(threading.active_count())
        s = conf.L2socket(iface=self.controller_port)
        # sendp(new_p_str, iface=self.controller_port, verbose=0)
        s.send(new_p_str)
        print port
    def processPacket(self, p):
        # hexdump(p)
        # print '.',
        p_str = str(p)

        # reason 1 means nat_int_ext_miss - any other reason is not valid
        if p_str[0] != '\x01':
            #print("Resubmit or Reason not valid")
            return

        try:
            p2 = Ether(p_str[6:])
            ip_hdr = p2['IP']
            tcp_hdr = p2['TCP']
        except:
            #print("could not do Ether")
            return

        #print("ready to insert new rules")
        #print(ip_hdr.src)
        #print(ip_hdr.dst)
        #print(tcp_hdr.sport)
        #print(tcp_hdr.dport)

        pktInfo = (ip_hdr.src,ip_hdr.dst,tcp_hdr.sport,tcp_hdr.dport)
        if pktInfo in self.processedList:
            #print "Rules for this connection pending..."
            PacketProcessor.natAndSend(self,p2,self.processedList[pktInfo])
            return

        matchIP = ip_hdr.src # Changing these values in natAndSend, so remember originals
        matchPort = tcp_hdr.sport # Changing these values in natAndSend, so remember originals

        PacketProcessor.natAndSend(self, p2, self.cur_tcp_port)
        self.processedList[pktInfo] = self.cur_tcp_port

        fromPortNo = ord(p_str[1])  # physical port that request came from
        fromPort = self.device_number + str(fromPortNo)
        #print("Request came from port: " + str(fromPort))
    
        ext_tcp_port = self.cur_tcp_port
        if (self.cur_tcp_port < 65535):
            self.cur_tcp_port += 1
        else:
            self.cur_tcp_port = 1025
    
        try:
            # sendTime = time.time() + 0.1
            #print "Adding Rules Start"
            #print RTEInterface
            # #print RTEInterface.System.GetVersion()
    
            # INT_TO_EXT
            # add a rule to a nat table - to hit int_ext_hit next time
            tbl_id = 'nat'
            rule_name = 'nat_int_ext_hit_' + str(ext_tcp_port)
            default_rule = False
            actions = '{  "type" : "nat_int_ext_hit",  "data" : { "port" : { "value" : "%s" }, "srcAddr" : {"value" : "%s" }, "srcPort" : {"value" : "%d" } } }' % \
                      (self.ext_port, self.router_ext_ip, ext_tcp_port)
            match = '{ "ipv4.srcAddr" : {  "value" : "%s", "mask" : "0xffffffff" }, "ipv4.dstAddr" : {  "value" : "%s", "mask" : "0xffffffff" }, "ipv4" : {  "value" : "valid" }, "standard_metadata.ingress_port" : {  "value" : "%s" }, "tcp.srcPort" : {  "value" : "%d", "mask" : "0xffff" }, "tcp.dstPort" : {  "value" : "%d", "mask" : "0xffff" }, "tcp" : {  "value" : "valid" } }' % \
                    (matchIP, ip_hdr.dst, fromPort, matchPort, tcp_hdr.dport)

            with THRIFT_API_LOCK:
                RTEInterface.Tables.AddRule(tbl_id, rule_name, default_rule, match, actions, 1)
                # RTEInterface.Tables.AddRule(tbl_id, rule_name, default_rule, match, actions, 1, 3)
    
            # EXT_TO_INT
            # add a rule to a nat table - to hit ext_int_hit on reply
            tbl_id = 'nat'
            rule_name = 'nat_ext_int_hit_' + str(ext_tcp_port)
            default_rule = False
            actions = '{  "type" : "nat_ext_int_hit",  "data" : { "port" : { "value" : "%s" } , "dstAddr" : {"value" : "%s" }, "dstPort" : {"value" : "%d" } } }' % \
                      (fromPort, matchIP, matchPort)
            match = '{ "ipv4.srcAddr" : {  "value" : "%s", "mask" : "0xffffffff" }, "ipv4.dstAddr" : {  "value" : "%s", "mask" : "0xffffffff" }, "ipv4" : {  "value" : "valid" }, "standard_metadata.ingress_port" : {  "value" : "%s" }, "tcp.srcPort" : {  "value" : "%d", "mask" : "0xffff" }, "tcp.dstPort" : {  "value" : "%d", "mask" : "0xffff" }, "tcp" : {  "value" : "valid" } }' % \
                    (ip_hdr.dst, self.router_ext_ip, self.ext_port, tcp_hdr.dport, ext_tcp_port)
    
            with THRIFT_API_LOCK:
                RTEInterface.Tables.AddRule(tbl_id, rule_name, default_rule, match, actions, 1)
                # RTEInterface.Tables.AddRule(tbl_id, rule_name, default_rule, match, actions, 1, 3)
    
        except Exception, err:
            print("Exception")
            print(err)
            # if args.debug_script:
            #           #print >> sys.stderr, traceback.format_exc()
            #    else:
            #         #print >> sys.stderr, "error: %s" % str(err)
            #    sys.exit(1)


        self.ruleNum += 1
        #print "Done Adding Rule: " + str(self.ruleNum)

def main():
    parser = argparse.ArgumentParser(description='P4 Firewall-Controller config')
    parser.add_argument('-i','--ip', help='External IP address - "192.168.0.1"', required=False,default="192.168.0.1")
    # parser.add_argument('-p','--ext-port', help='External port for rules - "v0.2"', required=False,default="v0.2")
    parser.add_argument('-p','--ext-port', help='External port for rules - "p1"', required=False,default="p1")
    # parser.add_argument('-c','--controller-port', help='Controller port - "vf0_1"', required=False,default="vf0_1")
    parser.add_argument('-c','--controller-port', help='Controller port - "vf0_1"', required=False,default="vf0_1")
    parser.add_argument('-r','--controller-port-rules', help='Controller port for rules - "v0.1"', required=False,default="v0.1")
    # parser.add_argument('-d','--device-number', help='Device number in case of using VFs - "v0."', required=False,default="v0.") #How would this work for physical ports? - Default " "?
    parser.add_argument('-d','--port-prefix', help='Port prefix for internal port - "v0." for VF or "p" for physical (DEFAULT: p)"', required=False,default="p")
    parser.add_argument('-o', '--rpc-port',dest='rpc_port', default='20206',type=int,help="Thrift RPC port (DEFAULT: 20206)")
    parser.add_argument('-s', '--rpc-server', dest='rpc_server', default='localhost', type=str, help="Thrift RPC host (DEFAULT: localhost)")
    parser.add_argument('-t', '--rule-timeout', dest='rule_timeout', default=1000, type=float, help="Rule Timeout - Rules will delete if not hit within t seconds (DEFAULT: 10 seconds)")
    parser.add_argument('-n', '--internal-ports', dest='internal_ports', default=1, type=float, help="Number of internal ports (DEFAULT: 1)")
    
    args = parser.parse_args()

    stopFlag = Event()
    thread = TimerThread(stopFlag, args.rule_timeout, args.internal_ports)
    thread.daemon = True
    thread.start()

    RTEInterface.Connect(args.rpc_server, args.rpc_port)
    ruleNum = 0
    pp = PacketProcessor(args.ip, 1025, args.ext_port, args.controller_port, 
        args.controller_port_rules, args.port_prefix,ruleNum)

    while(1):
        s = conf.L2socket(iface=args.controller_port)
        s.sniff(prn=pp)
    # sniff(iface=args.controller_port, prn=pp)

if __name__ == '__main__':
    main()