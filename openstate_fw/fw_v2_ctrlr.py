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
        MAX_PACKET_SIZE = 1488
        split_packet_count = (len(bin)/MAX_PACKET_SIZE)
        for i in range(0,split_packet_count+1):
            packet = Ether('aaaaaaaaaaaaaa000000')
            payload = bin[i*MAX_PACKET_SIZE:(i+1)*MAX_PACKET_SIZE]
            packet.add_payload(payload)
            sendp(packet, iface=self.controller_port, verbose=0)

    def run(self):
        while not self.stopped.wait(self.pollingTime):
            print("Memdump Poll")

            # rhitcount_dump = []
            rpubport_dump = []
            rpubip_dump = []
            rpvtport_dump = []
            rpvtip_dump = []
            portsUsedNow = {}

            # given_ports = self.al.symbols['_ports']
            rhitcount = self.al.symbols['_pif_register_reg_hit_count']
            
            rpubport = self.al.symbols['_pif_register_reg_public_port']
            rpubip = self.al.symbols['_pif_register_reg_public_ip']

            rpvtport = self.al.symbols['_pif_register_reg_private_port']
            rpvtip = self.al.symbols['_pif_register_reg_private_ip']

            for data in self.al.symbols.read(rpubport, data_type='I'):
                rpubport_dump.append(data)

            for data in self.al.symbols.read(rpubip, data_type='I'):
                rpubip_dump.append(data)

            for data in self.al.symbols.read(rpvtport, data_type='I'):
                rpvtport_dump.append(data)

            for data in self.al.symbols.read(rpvtip, data_type='I'):
                rpvtip_dump.append(data)

            for index, hit_count in enumerate(self.al.symbols.read(rhitcount, data_type='I')):
                # portsUsedNow.append((rpubip_dump[index],rpubport_dump[index],hit_count))
                if (hit_count != 0):
                    if (rpubip_dump[index] != 0): # public and private indexes shouldn't overlap - their hash differ?
                        portsUsedNow[index] = (rpubip_dump[index], rpubport_dump[index], hit_count)
                    elif (rpvtip_dump[index] != 0): # public and private indexes shouldn't overlap - their hash differ?
                        portsUsedNow[index] = (0, 0, hit_count) # unique ip/port comination to test for in Sandbox function

            # print portsUsedNow

            bin = ''
            for key, port in self.portsLastUsed.iteritems():
                try:
                    if  port[2] == portsUsedNow[key][2] and portsUsedNow[key][2] != 0:
                        print str(hex(port[0])) + " " + str(hex(port[1])) + " " + str(hex(port[2])) + " " + str(key) +" Timeout"
                        ip = '{:08x}'.format(port[0], 'x')
                        bin += ''.join(chr(int(str(ip)[i:i + 2], 16)) for i in range(0, len(str(ip)), 2))
                        bin += '\x00' + '\x00' + chr(port[1] / 256) + chr(port[1] % 256)
                        bin += chr((key/65536) / 256) + chr((key/65536) % 256) + chr((key%65536) / 256) + chr((key%65536) % 256) # 65536 wil have to change if STATE_MAP_SIZE changes
                except:
                    continue

            if bin != '':
                self.sendControllerPacket(bin)

            # self.al.symbols.write(rhitcount, rhitcount.contents.size * '\x00')
            self.portsLastUsed = portsUsedNow

def clearAll(al):
    given_ports = al.symbols['_ports']
    rpubport = al.symbols['_pif_register_reg_public_port']
    rpubip = al.symbols['_pif_register_reg_public_ip']
    rpvtport = al.symbols['_pif_register_reg_private_port']
    rpvtip = al.symbols['_pif_register_reg_private_ip']
    rstate = al.symbols['_pif_register_reg_state']
    rhitcount = al.symbols['_pif_register_reg_hit_count']

    al.symbols.write(rpubport, rpubport.contents.size * '\x00')
    al.symbols.write(given_ports, given_ports.contents.size * '\x00')
    al.symbols.write(rpubip, rpubip.contents.size * '\x00')
    al.symbols.write(rpvtport, rpvtport.contents.size * '\x00')
    al.symbols.write(rpvtip, rpvtip.contents.size * '\x00')
    al.symbols.write(rstate, rstate.contents.size * '\x00')
    al.symbols.write(rhitcount, rhitcount.contents.size * '\x00')

    curpubip = al.symbols['_cur_public_ip']
    curpubport = al.symbols['_cur_port']
    al.symbols.write(curpubip, curpubip.contents.size * '\x00')
    al.symbols.write(curpubport, 6*('\x01' + '\x04' + 2 * '\x00'))

    # al.symbols.write(rpubport, 8*'\xff',offset=8)

def main():
    parser = argparse.ArgumentParser(description='P4 Firewall-v2-Controller config')
    parser.add_argument('-i', '--ip', nargs='*', help='External IP addresses separated by spaces. Format: xxx.xxx.xxx.xxx', required=True, default="105.22.41.74") # find out how to set list
    # parser.add_argument('-n', '--num-ip', help='Number of used External IP addresses"', type=int, required=False,default=1)
    parser.add_argument('-c', '--closed-ports', nargs='*', help='List of closed ports - "1035, 1050"', required=False,default="1035")  # find out how to set list
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
        al.symbols.write(n, chr(len(args.ip)) + '\x00' * 7)
        bin = ''
        for ip in args.ip:
            bin += ''.join([chr(int(a)) for a in ip.split('.')])
        bin += (24 - len(bin)) * '\x00'
        i = al.symbols['_public_ips']
        al.symbols.write(i, bin)

        clearAll(al)

        while True:
            time.sleep(1)


if __name__ == '__main__':
    main()








