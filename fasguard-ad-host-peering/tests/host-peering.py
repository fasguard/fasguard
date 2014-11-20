# Generate a pcap file "host-peering-test.pcap" that tests out the
# Host Peering reference detector.

from scapy.all import *

# List of packets to include in the pcap file.
pkts = PacketList([])

# Initial time.
time = 1414711607.0

# Inter-packet arrival time in seconds.
timedelta = 1e-5

# Function to add a simple packet to the list of packets.
def a(src, dst):
    global time
    p = IP(src=src, dst=dst)/UDP(sport=1234, dport=1234)/"a"
    p.time = time
    time += timedelta
    pkts.append(p)

# Test the cleanup function by waiting MAX_EMPTY_GENERATIONS with no
# traffic.
a("192.168.1.1", "192.168.1.2")
time += 60
a("192.168.1.1", "192.168.1.3")
time += 60
a("192.168.1.1", "192.168.1.4")
time += 24 * 60 * 60 + 60

# Create a very low mean and standard deviation for 192.168.1.1 by
# waiting just under MAX_EMPTY_GENERATIONS with no traffic.
a("192.168.1.1", "192.168.1.2")
time += 24 * 60 * 60 - 2 * 60

# Create a high number of peers for 192.168.1.1 to make it anomalous.
x = 10
y = 0
for z in xrange(16):
    for w in xrange(256):
        a("192.168.1.1", "%d.%d.%d.%d" % (x, y, z, w))
time += 60

# Generate some traffic to be written to STIX files, now that
# 192.168.1.1 is anomalous.
a("192.168.1.1", "172.16.1.1")
a("192.168.1.1", "172.16.1.2")

wrpcap("host-peering-test.pcap", pkts)
