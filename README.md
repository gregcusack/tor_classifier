# Tor Classifier

## How it works
* The classifier.py program scrapes an input pcap and outputs the likelihood a user is using Tor
* Each IP in the captured packets are checked against a list of known Tor nodes collected from: 
	* https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv
* For every packet that contains a certificate, the Issuer and Subject URLs are extracted.
* The issuer and subject urls of the certificate have been used in the past to help detect Tor trafic (source: https://www.rsreese.com/detecting-tor-traffic-with-bro-network-traffic-analyzer/)
* The issuer/subject URLs of Tor traffic are random characters and have higher entropy than normal traffic certificate issuers/subjects
* As a result, the entropy of the URLs are calculated.  Most Tor traffic URLs have an entropy > 2.9.
	* Note, that this entropy threshold for calculating Tor traffic is likely to change as this project progresses.
		* For example, this threshold could be calculated as some sort of average across large amounts of Tor traffic
	* Entropy calculator found online at: http://pythonfiddle.com/shannon-entropy-calculation/
* In the end, the system makes uses the IP comparison and entropy calculator to make an estimation on how likely the packet contains Tor traffic.
* The system only ouputs possible Tor traffic for every client/server IP pair that it thinks may contain Tor traffic

## Setup
* You have two options here:
1. You can simply run: `python scrape_tor_list.py`
	1. This populates the tor_list from the website mentioned above
1. You can create a crontab that runs this script however often you want, so the list of known tor nodes is as updated as you would like
	1. Open crontab: `crontab -e`
	1. Set crontab: `* 1 * * * /path/to/python /path/to/scrape/function/scrape_tor_list.py>`
		1. The crontab setup above will execute at 1am every night, essentially updating your local Tor list every night.
		1. This crontab frequency can be changed however you would like by adjusting the: `* 1 * * *` part of the crontab
			1. For a more detailed explanation of how to use crontab, see: http://kvz.io/blog/2007/07/29/schedule-tasks-on-linux-using-crontab/
* Once your tor_list.txt is updated, it is time to find Tor traffic in your PCAP!
	1. Run: `python classifier.py /path/to/pcap/file.pcap`

## Getting a PCAP
* If you just want to look at your own traffic going in and out of your computer, _tcpdump_ is a pretty good option
	1. If you are on MacOS, run: `tcpdump -i en0 -w /path/to/save/pcap/file.pcap`

# This is still a work in progress so comments, issues, suggestions, etc are 5sure welcomed!