import urllib2
import requests
import csv

url = "https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv"
response = urllib2.urlopen(url)
cr = csv.reader(response)
writer = csv.writer(open('/Users/gregcusack/Desktop/ECEN 5003 (Wustrow)/Tor Presentation/tor_ips.txt', 'w'))
for row in cr:
    writer.writerow(row)