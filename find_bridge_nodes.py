from scapy.all import *
import os
import binascii
import math

#Taken from: http://freecode.com/projects/revelation/
def new_entropy(string):
        "Calculates the Shannon entropy of a string"
        # get probability of chars in string
        prob = [ float(string.count(c)) / len(string) for c in dict.fromkeys(list(string)) ]
        # calculate the entropy
        entropy = - sum([ p * math.log(p) / math.log(2.0) for p in prob ])
        return entropy

def entropy_ideal(length):
        "Calculates the ideal Shannon entropy of a string with given length"
        prob = 1.0 / length
        return -1.0 * length * prob * math.log(prob) / math.log(2.0)

#BEGIN
if __name__ == '__main__':
	RATIO_THRESHOLD = 0.26
	pkts = sys.argv[1]
	ip_list = []
	#Use scapy to read the input pcap into a pkt_list
	pkt_list = rdpcap(pkts)
	d = {}
	for pack in pkt_list:
		if IP in pack:
			#print(pack[IP].dst)
			if pack[IP].dst not in d:
				d[pack[IP].dst] = []
			d[pack[IP].dst].append(bytearray(str(pack)))

	big_arr = []
	IP_entropy_dict = {}
	for k, v in d.items():
		num_v = len(v)
		min_len = len(min(v, key=len))
		#print(min_len)
		array = []
		for i in range(min_len):
			res = v[0][i]
			for x in range(num_v-1):
				res = res ^ v[x+1][i]
			array.append(str(res))
		hex_val = str(bytearray(int(y,10) for y in array)).encode("HEX")
		#print(hex_val)
		len_bin = len(hex_val)*4
		bin_arr = (bin(int(hex_val, 16))[2:]).zfill(len_bin)
		#exit()
		#print(bin_arr)
		act_ideal_arr = []
		act_ideal_arr.append(new_entropy(bin_arr))
		act_ideal_arr.append(entropy_ideal(len_bin))
		IP_entropy_dict[k] = act_ideal_arr
		num_zeros = bin_arr.count('0')
		num_ones = bin_arr.count('1')
		ratio = num_ones/float(num_zeros) #want to be small to ID Bridge nodes
		if ratio > RATIO_THRESHOLD:
			print("IP: {}".format(k))
			print("0s: {}, 1s: {}".format(num_zeros, num_ones))
			print("Ratio (1s/0s): {} (higher is more random)".format(ratio))
			print("\n")
