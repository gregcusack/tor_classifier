import urllib2
import requests
import csv

url = "https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv"
response = urllib2.urlopen(url)
cr = csv.reader(response)
writer = csv.writer(open('/home/greg/Desktop/ECEN_5003_Wustrow/tor_classifier/tor_ips.txt', 'w'))
for row in cr:
    writer.writerow(row)
