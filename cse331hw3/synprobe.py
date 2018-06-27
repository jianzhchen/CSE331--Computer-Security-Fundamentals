import argparse
from scapy.all import *

def scanone(ip, port):
    fakeport = 12345
    fakeseqnum = 1234

    tcp = TCP(sport=fakeport, dport=port, flags="S", seq=fakeseqnum)
    recevpkt = sr1(ip / tcp, timeout=1, verbose=0)

    if recevpkt is None or recevpkt[TCP].flags != "SA":
        return

    # open, send an ACK
    tcp = TCP(sport=fakeport, dport=port, flags="A", seq=recevpkt["TCP"].ack + 1, ack=recevpkt["TCP"].seq + 1)
    recevpkt2 = sr1(ip / tcp, timeout=1, verbose=0)

    # case1
    if recevpkt2.haslayer("Raw"):
        return hexdump(str(recevpkt2.getlayer("Raw").load))

    # case2
    # send some payload, get index.html
    payload = Raw("GET /index.html HTTP/1.1 \r\n\r\n")
    tcp = TCP(sport=fakeport, dport=port, flags="PA", seq=recevpkt["TCP"].ack + 1, ack=recevpkt["TCP"].seq + 1)
    recevpkt2 = sr1(ip / tcp / payload, timeout=1, verbose=0)
    
    if recevpkt2 is None:
        return "NO RAW RETURNED";
    return hexdump(str(recevpkt2))

def hexdump(src, length=16):
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
    lines = []
    for c in xrange(0, len(src), length):
        chars = src[c:c + length]
        hex = ' '.join(["%02x" % ord(x) for x in chars])
        printable = ''.join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or '.') for x in chars])
        lines.append("%04x  %-*s  %s\n" % (c, length * 3, hex, printable))
    return ''.join(lines)

def scanmain(iprange, ports):
    for ip in iprange:
        print "=======Scanning IP: %s =======" % ip.dst
        for port in ports:
            try:
                returnhex = scanone(ip, port)
                if returnhex is not None:
                    print "%s:%d\t OPEN" % (ip.dst,port)
                    print "%s" % returnhex
            except Exception as e:
                print "Scapy ERROR {}".format(e)


def main():
    parser = argparse.ArgumentParser(description="Service fingerprinting")
    parser.add_argument("-p", help="The range of ports to be scanned Ex: 0-100")
    parser.add_argument("target",
                        help="target ip or subnet to scan. Ex: 192.168.0.0/24can be either a single IP address or a whole subnet (e.g.,192.168.0.0/24).")
    args = parser.parse_args()

    try:
        iprange = IP(dst=args.target)
    except Exception as e:
        print "target ip parse failed"
        return

    ports = args.p

    if ports is None:
        ports = [80, 23, 443, 8080, 22, 140]
    else:
        try:
            if "-" in ports:
                ports = ports.split("-")
                ports = range(int(ports[0]), int(ports[1])+1)
            if type(ports) is str:
                ports = [int(ports)]
        except:
            print "target port range parse failed"
            return

    scanmain(iprange, ports)

main()
