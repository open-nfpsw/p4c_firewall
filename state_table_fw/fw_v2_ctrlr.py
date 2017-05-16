import nfp_al
import time
import threading
import argparse
from threading import Event
from scapy.all import *


class StateTimeout(threading.Thread):
    def __init__(self, event, al, pollingTime,used_ips,portsLastUsed,controller_port):
        threading.Thread.__init__(self)
        self.stopped = event
        self.al = al
        self.pollingTime = pollingTime
        self.used_ips = used_ips
        self.portsLastUsed = portsLastUsed
        self.controller_port = controller_port

    def sendControllerPacket(self,bin):
        packet = Ether('aaaaaaaaaaaaaa000000')
        sendp(packet, iface=self.controller_port, verbose=0)

    def run(self):
        while not self.stopped.wait(self.pollingTime):
            print("Timeout Poll")

            self.sendControllerPacket(bin)


def clearAll(al):
    given_ports = al.symbols['_ports']
    al.symbols.write(given_ports, given_ports.contents.size * '\x00')

    curpubip = al.symbols['_cur_public_ip']
    curpubport = al.symbols['_cur_port']
    al.symbols.write(curpubip, curpubip.contents.size * '\x00')
    al.symbols.write(curpubport, 16*('\x01' + '\x04' + 2 * '\x00'))


    statehash = al.symbols['_state_hashtable'];
    al.symbols.write(statehash, statehash.contents.size * '\x00')

def main():
    parser = argparse.ArgumentParser(description='P4 Firewall-v2-Controller config')
    parser.add_argument('-i', '--ip', nargs='*', help='External IP addresses separated by spaces. Format: xxx.xxx.xxx.xxx', required=True, default="105.22.41.74")
    parser.add_argument('-t', '--state-timeout', help='Polling Time timeout state', type=float, required=False,default=30)  # find out how to set list
    parser.add_argument('-n', '--device-number', dest='dev_num', default='0', type=int,help="Device Number (DEFAULT: 0)")
    parser.add_argument('-p', '--controller-port', help='Controller port - "vf0_2"', required=False, default="vf0_2")
    args = parser.parse_args()

    with nfp_al.ConnectionCtx(args.dev_num, connect_url='tcp://localhost:20606') as al:

        portsLastUsed = {}

        stopFlag = Event()
        stateTimeout = StateTimeout(stopFlag, al, args.state_timeout,len(args.ip),portsLastUsed,args.controller_port)
        stateTimeout.daemon = True
        stateTimeout.start()

        # Initialize public IPs available to hand out:
        n = al.symbols['_num_used_public_ips']
        al.symbols.write(n, chr(len(args.ip)) + '\x00' * 17)
        bin = ''
        for ip in args.ip:
            bin += ''.join([chr(int(a)) for a in ip.split('.')])
        bin += (64 - len(bin)) * '\x00'
        i = al.symbols['_public_ips']
        al.symbols.write(i, bin)

        clearAll(al)

        while True:
            time.sleep(1)


if __name__ == '__main__':
    main()








