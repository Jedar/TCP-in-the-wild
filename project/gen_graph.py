from scapy.all import *
import matplotlib.pyplot as plt

#Change this to be your pcap file
#You can capture a pcap file with wireshark or tcpdump
#https://support.rackspace.com/how-to/capturing-packets-with-tcpdump/
FILE_TO_READ = '/Users/Alex/Desktop/test.pcapng'

packets = rdpcap(FILE_TO_READ)
packet_list = []
times = []
base = 0
server_port = 15441
num_packets = 0

for packet in packets:
	payload = packet[Raw].load

	if(IP in packet and packet[IP].dport == server_port and 15441 == int.from_bytes(payload[:4], byteorder='big')):
		mask = int.from_bytes(payload[20:21], byteorder='big')
		if(mask == 0):
			num_packets = num_packets + 1
		elif((mask & 4) == 4):
			num_packets = num_packets - 1
		time = packet.time
		if base == 0:
			base = time
		packet_list.append(num_packets)
		times.append(time - base)

#https://matplotlib.org/users/pyplot_tutorial.html for how to format and make a good quality graph.
print(packet_list)
plt.scatter(packet_list, times)
plt.show()
