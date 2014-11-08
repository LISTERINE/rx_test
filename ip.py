from scapy.all import *
from rx.subjects import Subject
import sys
from pdb import set_trace

sub = Subject()

# Filter set
udp = sub.select(lambda x:x).where(lambda x: UDP in x)
# Action when data makes it through the filter set
udp.subscribe(lambda x: sys.stdout.write('UDP\n'))

# Find packets with TCP, a dport of 80, and a length between 50-65
http = sub.select(lambda x:x
         ).where(lambda x: TCP in x
         ).where(lambda x: x[IP].dport == 80
         ).where(lambda x: int(x[IP].len) < 65
         ).where(lambda x: int(x[IP].len) > 50)
# If found, print the layers of the packet
http.subscribe(lambda x: sys.stdout.write(str(list_layers(x))+"\n"))


def iter_packet(packet):
    yield packet
    while packet.payload:
        packet = packet.payload
        yield packet

def list_layers(packet):
    return [L.name for L in iter_packet(packet)]


def push(packet):
    #set_trace()
    sub.on_next(packet)

sniff(prn=push)
