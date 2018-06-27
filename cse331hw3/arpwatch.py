import argparse
from scapy.all import *

def main():
    parser = argparse.ArgumentParser(description="ARP cache poisoning detector")
    parser.add_argument("-i", help="Live capture from the network device <interface> (e.g., eth0). If not specified, arpwatch.py should automatically select a default interface tolisten on.")
    args = parser.parse_args()
    
    arp_table=[]
    interface=""
    if args.i is not None:
        interface=args.i
    cmd="arp -a"
    p=subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    output, errors = p.communicate()
    if output is not None :
        for i in output.split("\n"):
            entry = i.split(" ")
            if len(entry)>=7:
                if interface=="":
                    interface=entry[6]
                if interface==entry[6]:
                    arp_table.append([entry[1][1:-1],entry[3]])
                               
    print "ARP cache poisoning detector on interface: %s"  %interface

    def arpcheck(pkt):
        if pkt[ARP].op == 2:
            for entry in arp_table:
                if entry[0] == pkt[ARP].psrc:
                    if(entry[1]!=pkt[ARP].hwsrc):
                        print '{} changed from {} to {}'.format(entry[0],entry[1],pkt[ARP].hwsrc)
    
    sniff(iface=interface, prn=arpcheck, filter="arp", store=0)
    
main()