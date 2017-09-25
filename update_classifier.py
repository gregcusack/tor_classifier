from scapy.all import *
import math

def istorCert(iss_url, subj_url):
	if iss_url == subj_url:
		return False
	return True

def get_cert_urls(packet):
	try:
		load = packet[Raw].load
	except IndexError:
		return False
	try:
		issuer_begin_index = load.index('www.')
	except ValueError:
		return False
	for i in range(issuer_begin_index+4, len(load)): #first w to end of load
		if load[i] == '.':
			break
	issuer_url = load[issuer_begin_index+4:i]
	
	load_next = load[i+1:]
	try:
		subj_begin_index = load_next.index('www.')
	except ValueError:
		return False

	for k in range(subj_begin_index+4, len(load_next)):
		if load_next[k] == '.':
			break
	subj_url = load_next[subj_begin_index+4:k]

	if istorCert(issuer_url, subj_url):
		return [issuer_url, subj_url]
	return False

def isTorSrc(packet):
	if packet[IP].src in ip_list:
		return True
	return False

def isTorDst(packet):
	if packet[IP].dst in ip_list:
		return True
	return False

#Entropy fcn taken from: http://pythonfiddle.com/shannon-entropy-calculation/
def range_bytes (): return range(256)
def entropy(data, iterator=range_bytes):
	if not data:
		return 0
	entropy = 0
	for x in iterator():
		p_x = float(data.count(chr(x)))/len(data)
		if p_x > 0:
			entropy += - p_x*math.log(p_x, 2)
	return entropy

def get_client_IP(packet, list_flag):
	if list_flag == 1:
		return packet[IP].dst
	return packet[IP].src

def get_server_IP(packet, list_flag):
	if list_flag == 1:
		return packet[IP].src
	return packet[IP].dst

def print_highly_likely(client_ip, server_ip):
	print("Confidence Level: HIGHLY LIKELY")
	print("Client with IP: {} (User)".format(client_ip))
	print("Server with IP: {} (Tor Node)".format(server_ip))
	print("Decision based on:")
	print("\t1.) Source or Destination IP found in list of known Tor IPs")
	print("\t2.) Certificate issuer and subject entropies are higher than normal for typical traffic\n")

def print_likely_no_cert(client_ip, server_ip):
	print("Confidence Level: LIKELY")
	print("Client with IP: {} (User)".format(client_ip))
	print("Server with IP: {} (Tor Node)".format(server_ip))
	print("Decision based on:")
	print("\t1.) Source or Destination IP found in list of known Tor IPs")
	print("\t2.) Packet does not contain certificate, so issuer/subject entropy not calculated\n")

def print_likely_cert(client_ip, server_ip):
	print("Confidence Level: LIKELY")
	print("Client with IP: {} (User)".format(client_ip))
	print("Server with IP: {} (Tor Node)".format(server_ip))
	print("Decision based on:")
	print("\t1.) Source or Destination IP found in list of known Tor IPs")
	print("\t2.) Certificate issuer and subject entropy is lower than normal for typical Tor traffic\n")

def print_inconclusive(client_ip, server_ip):
	print("Confidence Level: INCONCLUSIVE")
	print("Client with IP: {} (User)".format(client_ip))
	print("Server with IP: {} (Tor Node)".format(server_ip))
	print("Decision based on:")
	print("\t1.) Neither Source nor Destination IPs found in list of known Tor nodes")
	print("\t2.) Certificate issuer and subject entropies are higher than normal for typical traffic\n")

def tor_client_server_list(client_ip, server_ip, usr_list):
	if (client_ip, server_ip) in usr_list:
		return True
	return False

if __name__ == '__main__':
	ENTROPY_THRESHOLD = 2.9
	pkts = sys.argv[1]
	ip_list = []
	with open("tor_ips.txt","r") as file_torlist:
		for line in file_torlist:
			line = line[:-1]
			if '\r' in line or '\n' in line:
				ip_list.append(line[:-1])
			else:
				ip_list.append(line)
	pkt_list = rdpcap(pkts)

	tor_comm = {}
	pkt_count = 0
	for packet in pkt_list:
		pkt_count += 1
		list_flag = 0
		entropy_flag = False
		if IP in packet:
			if isTorSrc(packet):
				list_flag = 1
			if isTorDst(packet):
				list_flag = 2
			url = get_cert_urls(packet)
			if url:
				if entropy(url[0]) > ENTROPY_THRESHOLD and entropy(url[1]) > ENTROPY_THRESHOLD:
					entropy_flag = True
			client_ip = get_client_IP(packet, list_flag)
			server_ip = get_server_IP(packet, list_flag)
			in_list = tor_client_server_list(client_ip, server_ip, tor_comm)
			if list_flag and entropy_flag:
				if not in_list:
					tor_comm[(client_ip, server_ip)] = 1
				elif tor_comm[(client_ip, server_ip)] > 1:
					tor_comm[(client_ip, server_ip)] = 1
			elif list_flag and url:
				if not in_list:
					tor_comm[(client_ip, server_ip)] = 2
				elif tor_comm[(client_ip, server_ip)] > 3:
					tor_comm[(client_ip, server_ip)] = 2
			elif list_flag and not url:
				if not in_list:
					tor_comm[(client_ip, server_ip)] = 3
				elif tor_comm[(client_ip, server_ip)] > 3:
					tor_comm[(client_ip, server_ip)] = 3
			elif entropy_flag:
				if not in_list:
					tor_comm[(client_ip, server_ip)] = 4
	if not tor_comm:
		print("No Tor Traffic Detected")

	for k, v in tor_comm.items():
		print("\nTOR TRAFFIC FOUND!")
		if v == 1:
			print_highly_likely(k[0], k[1])
		elif v == 2:
			print_likely_cert(k[0], k[1])
		elif v == 3:
			print_likely_no_cert(k[0], k[1])
		elif v == 4:
			print_inconclusive(k[0], k[1])
		print("-----------------------------------------------------------------")