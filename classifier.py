from scapy.all import *
import math

# Tor certs don't have same issuer and subject, but normal traffic does (not always though)
def istorCert(iss_url, subj_url):
	if iss_url == subj_url:
		return False
	return True

#return a packets issuer/subject urls (if there are any!)
def get_cert_urls(packet):
	# cert is in raw of packet
	try:
		load = packet[Raw].load
	except IndexError:
		return False

	if len(load) < 73: #make sure raw long enough
		return False

	#look for server hello message
	if load[0].encode("HEX") <> '16' or load[5].encode("HEX") <> '02':
		return False
	print("------------ Cert packet! -------------")
	#look for web urls in raw
	try:
		issuer_begin_index = load.index('www.')
	except ValueError:
		return False
	# get first URl which corresponds to the url of the certificate issuer
	for i in range(issuer_begin_index+4, len(load)): #first w to end of load
		if load[i] == '.':
			break
	issuer_url = load[issuer_begin_index+4:i]
	
	#look for next url, corresponds to url of the certificate subject
	load_next = load[i+1:]
	try:
		subj_begin_index = load_next.index('www.')
	except ValueError:
		return False
	#grab that second url
	for k in range(subj_begin_index+4, len(load_next)):
		if load_next[k] == '.':
			break
	subj_url = load_next[subj_begin_index+4:k]

	#check to see if they are the same
	if istorCert(issuer_url, subj_url):
		return [issuer_url, subj_url]
	return False

#check if source of packet is in the Tor list
def isTorSrc(packet):
	if packet[IP].src in ip_list:
		return True
	return False

#check if destination of packet is in the Tor list
def isTorDst(packet):
	if packet[IP].dst in ip_list:
		return True
	return False

#Calculate entropy of certificate URLs
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

#Print message to screen based on data found
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

#BEGIN
if __name__ == '__main__':
	ENTROPY_THRESHOLD = 2.9
	pkts = sys.argv[1]
	ip_list = []
	#Open list of tor IPs and put them into a list, removing all carriage returns/new lines
	with open("tor_ips.txt","r") as file_torlist:
		for line in file_torlist:
			line = line[:-1]
			if '\r' in line or '\n' in line:
				ip_list.append(line[:-1])
			else:
				ip_list.append(line)
	#Use scapy to read the input pcap into a pkt_list
	pkt_list = rdpcap(pkts)
	"""
	pkt = pkt_list[4649]
	raw = pkt[Raw].load
	if raw[67].encode("HEX") <> '16':
		print("bad")
	if raw[72].encode("HEX") <> '0b':
		print("also bad")
	print(raw[67].encode("HEX"))
	print(raw[72].encode("HEX"))
	exit()
	"""
	tor_comm = {}
	pkt_count = 0
	#iterate through evey packet in the pcap file
	for packet in pkt_list:
		pkt_count += 1
		list_flag = 0
		entropy_flag = False
		#check to see if there is an IP segment in the packet
		if IP in packet:
			#check to see if the Tor source or destination is a Tor node (found in the tor list)
			if isTorSrc(packet):
				list_flag = 1
			if isTorDst(packet):
				list_flag = 2
			#get the issuer/subject urls of the packets certificate
			#this will also check to see if the packet actually has a certificate
			url = get_cert_urls(packet)
			#if there is a certifiacte, calculate the entropies of the certificate URLs
			if url:
				if entropy(url[0]) > ENTROPY_THRESHOLD and entropy(url[1]) > ENTROPY_THRESHOLD:
					entropy_flag = True
			#get the client/server IP of the packet
			client_ip = get_client_IP(packet, list_flag)
			server_ip = get_server_IP(packet, list_flag)
			#check to see if the client/server ip tuple is in the dictionary
			in_list = tor_client_server_list(client_ip, server_ip, tor_comm)
			#Each client/server pair has a priority value associated with it
			# 1: larget priority, server or client found in tor list and high certificat entropy
			# 2: next priorty is server or client in tor list and either certiciate is found and
			#	 has lower than expected entropy for Tor communication or there is no cert in the
			#    packet
			# 3: Basically same as 2 --> don't differentiate tor use likelihood between no certificate
			#	 and lower than expected entropy of the certificate
			# 4: Neither client nor source found in tor list, but the certificate in the packet has
			#    higher than expected entropy for normal traffic
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

	# Iterate through the tor client/server list and print findings
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