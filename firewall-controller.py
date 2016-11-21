from scapy.all import *
import argparse
import time
import threading
from threading import Event

try:
    # running from tools
    from nfp_pif_rte.RTEInterface import RTEInterface
except ImportError, err:
    # running inplace
    from RTEInterface import RTEInterface


from sdk6_rte import RunTimeEnvironment
from sdk6_rte.ttypes import *

from urlparse import urlparse
from thrift.transport import TTransport
from thrift.transport import TZlibTransport
from thrift.transport import TSocket
#from thrift.transport import TSSLSocket
from thrift.transport import THttpClient
from thrift.protocol import TBinaryProtocol


parser = argparse.ArgumentParser(description='P4 Firewall-Controller config')
parser.add_argument('-i','--ip', help='External IP address - "192.168.0.1"', required=False,default="192.168.0.1")
# parser.add_argument('-p','--ext-port', help='External port for rules - "v0.2"', required=False,default="v0.2")
parser.add_argument('-p','--ext-port', help='External port for rules - "p1"', required=False,default="p1")
# parser.add_argument('-c','--controller-port', help='Controller port - "vf0_1"', required=False,default="vf0_1")
parser.add_argument('-c','--controller-port', help='Controller port - "vf0_1"', required=False,default="vf0_1")
parser.add_argument('-r','--controller-port-rules', help='Controller port for rules - "v0.1"', required=False,default="v0.1")
# parser.add_argument('-d','--device-number', help='Device number in case of using VFs - "v0."', required=False,default="v0.") #How would this work for physical ports? - Default " "?
parser.add_argument('-d','--device-number', help='Device prefix - "v0. or p (DEFAULT: p)"', required=False,default="p")
parser.add_argument('-o', '--rpc-port',dest='rpc_port', default='20206',type=str,help="Thrift RPC port (DEFAULT: 20206)")
parser.add_argument('-s', '--rpc-server', dest='rpc_server', default='localhost', type=str, help="Thrift RPC host (DEFAULT: localhost)")
parser.add_argument('-t', '--rule-timeout', dest='rule_timeout', default=1000, type=float, help="Rule Timeout - Rules will delete if not hit within t seconds (DEFAULT: 10 seconds)")
parser.add_argument('-n', '--internal-ports', dest='internal_ports', default=1, type=float, help="Number of internal ports (DEFAULT: 1)")

args = vars(parser.parse_args())

ROUTER_EXT_IP = args['ip']  # should get IP through argument on startup
CUR_TCP_PORT = 1025
EXT_PORT = args['ext_port']
CONTROLLER_PORT = args['controller_port']
CONTROLLER_PORT_RULES = args['controller_port_rules']
DEVICE_NUMBER = args['device_number']
rpc_port = args['rpc_port']
rpc_server = args['rpc_server']
rule_timeout = args['rule_timeout']
internal_ports = args['internal_ports']


class TimerThread(threading.Thread):
    def __init__(self, event):
        threading.Thread.__init__(self)
        self.stopped = event

    def run(self):
        while not self.stopped.wait(rule_timeout):
            print("Timeout poll")

            RTEInterface.Connect(rpc_server, rpc_port)

            counterList = RTEInterface.Counters.ListP4Counters()
            tableId = counterList[0].tableid # Only have 1 table with counters in this example
            ruleList = RTEInterface.Tables.ListRules(tableId)
            counterValueList = []

            for i in range(internal_ports + 1,len(ruleList)):
                print(ruleList[i].rule_name)
                counterValueList.append(RTEInterface.Counters.GetP4Counter(counterList[0])[i])
                if RTEInterface.Counters.GetP4Counter(counterList[0])[i] == 0:
                    print("Deleting rule: " + ruleList[i].rule_name)
                    RTEInterface.Tables.DeleteRule(tableId, ruleList[i].rule_name, False, "{}", "{}")
                    time.sleep(0.1)

            # print(counterList)
            # print(counterList[0].name)
            print(counterValueList)

            RTEInterface.Counters.ClearAllP4Counters()


stopFlag = Event()
thread = TimerThread(stopFlag)
thread.start()

# this will stop the timer
# stopFlag.set()




class FuncThread(threading.Thread):
    def __init__(self, target, *args):
        self._target = target
        self._args = args
        threading.Thread.__init__(self)

    def run(self):
        self._target(*self._args)



def processPacket(p):
    hexdump(p)
    p_str = str(p)

    global ROUTER_EXT_IP
    global CUR_TCP_PORT
    global EXT_PORT
    global CONTROLLER_PORT
    global CONTROLLER_PORT_RULES
    global DEVICE_NUMBER

    # reason 1 means nat_int_ext_miss - any other reason is not valid
    if p_str[0] != '\x01':
        print("Resubmit or Reason not valid")
        return

    fromPortNo = ord(p_str[1])  # physical port that request came from
    fromPort = DEVICE_NUMBER + str(fromPortNo)
    print("Request came from port: " + str(fromPort))

    try:
        p2 = Ether(p_str[6:])
        ip_hdr = p2['IP']
        tcp_hdr = p2['TCP']
    except:
        print("could not do Ether")
        return

    print("ready to insert new rules")
    print(ip_hdr.src)
    print(ip_hdr.dst)
    print(tcp_hdr.sport)
    print(tcp_hdr.dport)

    ext_tcp_port = CUR_TCP_PORT
    if (CUR_TCP_PORT < 65535):
        CUR_TCP_PORT += 1
    else:
        CUR_TCP_PORT = 1025




    try:
        # sendTime = time.time() + 0.1
        print "Adding Rules Sart"
        print RTEInterface
        RTEInterface.Connect(rpc_server, rpc_port)
        print RTEInterface.System.GetVersion()

        # INT_TO_EXT
        # add a rule to a nat table - to hit int_ext_hit next time
        tbl_id = 'nat'
        rule_name = 'nat_int_ext_hit_' + str(ext_tcp_port)
        default_rule = False
        actions = '{  "type" : "nat_int_ext_hit",  "data" : { "port" : { "value" : "%s" }, "srcAddr" : {"value" : "%s" }, "srcPort" : {"value" : "%d" } } }' % \
                  (EXT_PORT, ROUTER_EXT_IP, ext_tcp_port)
        match = '{ "ipv4.srcAddr" : {  "value" : "%s", "mask" : "0xffffffff" }, "ipv4.dstAddr" : {  "value" : "%s", "mask" : "0xffffffff" }, "ipv4" : {  "value" : "valid" }, "standard_metadata.ingress_port" : {  "value" : "%s" }, "tcp.srcPort" : {  "value" : "%d", "mask" : "0xffff" }, "tcp.dstPort" : {  "value" : "%d", "mask" : "0xffff" }, "tcp" : {  "value" : "valid" } }' % \
                (ip_hdr.src, ip_hdr.dst, fromPort, tcp_hdr.sport, tcp_hdr.dport)

        RTEInterface.Tables.AddRule(tbl_id, rule_name, default_rule, match, actions, 1)

        # Packet from controller should also hit NAT
        # add a rule to a nat table - to get hit from controller
        tbl_id = 'nat'
        rule_name = 'nat_int_ext_hit_' + str(ext_tcp_port) + "_controller"
        default_rule = False
        actions = '{  "type" : "nat_int_ext_hit",  "data" : { "port" : { "value" : "%s" } , "srcAddr" : {"value" : "%s" }, "srcPort" : {"value" : "%d" } } }' % \
                  (EXT_PORT, ROUTER_EXT_IP, ext_tcp_port)
        match = '{ "ipv4.srcAddr" : {  "value" : "%s", "mask" : "0xffffffff" }, "ipv4.dstAddr" : {  "value" : "%s", "mask" : "0xffffffff" }, "ipv4" : {  "value" : "valid" }, "standard_metadata.ingress_port" : {  "value" : "%s" }, "tcp.srcPort" : {  "value" : "%d", "mask" : "0xffff" }, "tcp.dstPort" : {  "value" : "%d", "mask" : "0xffff" }, "tcp" : {  "value" : "valid" } }' % \
                (ip_hdr.src, ip_hdr.dst, CONTROLLER_PORT_RULES, tcp_hdr.sport, tcp_hdr.dport)

        RTEInterface.Tables.AddRule(tbl_id, rule_name, default_rule, match, actions, 1)

        # EXT_TO_INT
        # add a rule to a nat table - to hit ext_int_hit on reply
        tbl_id = 'nat'
        rule_name = 'nat_ext_int_hit_' + str(ext_tcp_port)
        default_rule = False
        actions = '{  "type" : "nat_ext_int_hit",  "data" : { "port" : { "value" : "%s" } , "dstAddr" : {"value" : "%s" }, "dstPort" : {"value" : "%d" } } }' % \
                  (fromPort, ip_hdr.src, tcp_hdr.sport)
        match = '{ "ipv4.srcAddr" : {  "value" : "%s", "mask" : "0xffffffff" }, "ipv4.dstAddr" : {  "value" : "%s", "mask" : "0xffffffff" }, "ipv4" : {  "value" : "valid" }, "standard_metadata.ingress_port" : {  "value" : "%s" }, "tcp.srcPort" : {  "value" : "%d", "mask" : "0xffff" }, "tcp.dstPort" : {  "value" : "%d", "mask" : "0xffff" }, "tcp" : {  "value" : "valid" } }' % \
                (ip_hdr.dst, ROUTER_EXT_IP, EXT_PORT, tcp_hdr.dport, ext_tcp_port)

        RTEInterface.Tables.AddRule(tbl_id, rule_name, default_rule, match, actions, 1)



    except Exception, err:
        print("Exception")
        print(err)
        # if args.debug_script:
        #           print >> sys.stderr, traceback.format_exc()
        #    else:
        #         print >> sys.stderr, "error: %s" % str(err)
        #    sys.exit(1)

    # packet already processed so don't process again - resubmit so reason won't be valid anymore
    new_p_str = '\x00' + '\x00' + p_str[2:]
    # this is in different thread, so can sleep. Better would be if RTE can let know when rule is added.
    time.sleep(2)
    print "threading.active_count " + str(threading.active_count())
    sendp(new_p_str, iface=CONTROLLER_PORT, verbose=0)


def processPacketInNewThread(x) :
    t1 = FuncThread(processPacket, x)
    t1.start()
#    t1.join() # seems like this waits for function to finish before continuing

def main():
    global CONTROLLER_PORT
    sniff(iface=CONTROLLER_PORT, prn=lambda x: processPacketInNewThread(x))


if __name__ == '__main__':
    main()