"""
import ping, socket
try:
	result = ping.do_one("www.r3w7ps2pdhkl.com",1,1)
except socket.error, e:
	print("Error: {}".format(e))
"""
import os
hostname = 'www.vpsdfsdfn.co'
#response = os.system("ping -c 1 -W 1 " + hostname)
#response = os.system("ping -c 1 -i 0.2 " + hostname)
response = os.system("fping " + hostname)

if response == 0:
	print("Hostname all good")
else:
	print("Host is bad")