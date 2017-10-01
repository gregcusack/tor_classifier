# Tor Classifier

## How it works
* The classifier.py program scrapes an input pcap and outputs the likelihood a user is using Tor
* Each IP in the captured packets are checked against a list of known Tor nodes collected from: 
	* https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv
* For every packet that contains a certificate, the Issuer and Subject URLs are extracted.
* The issuer and subject urls of the certificate have been used in the past to help detect Tor trafic (source: https://www.rsreese.com/detecting-tor-traffic-with-bro-network-traffic-analyzer/)
* The issuer/subject URLs of Tor traffic are random characters and have higher entropy than normal traffic certificate issuers/subjects
* As a result, the entropy of the URLs are calculated.  Most Tor traffic URLs have an entropy > 3.0.
	* Note, that this entropy threshold for calculating Tor traffic is likely to change as this project progresses.
		* For example, this threshold could be calculated as some sort of average across large amounts of Tor traffic
	* Entropy calculator found online at: http://pythonfiddle.com/shannon-entropy-calculation/
* The Certificate Issuer URL is also pinged using `fping`
	* This is done to add another check for certificate validity
* In the end, the system makes uses the IP comparison and entropy calculator to make an estimation on how likely the packet contains Tor traffic.
* The system only ouputs possible Tor traffic for every client/server IP pair that it thinks may contain Tor traffic

## Setup
* You have two options here:
1. You can simply run: `python scrape_tor_list.py`
	1. This populates the tor_list from the website mentioned above
1. You can create a crontab that runs this script however often you want, so the list of known tor nodes is as updated as you would like
	1. Open crontab: `crontab -e`
	1. Set crontab: `0 1 * * * /path/to/python /path/to/scrape/function/scrape_tor_list.py>`
		1. The crontab setup above will execute at 1am every night, essentially updating your local Tor list every night.
		1. This crontab frequency can be changed however you would like by adjusting the: `0 1 * * *` part of the crontab
			1. For a more detailed explanation of how to use crontab, see: http://kvz.io/blog/2007/07/29/schedule-tasks-on-linux-using-crontab/
* Once your tor_list.txt is updated, it is time to find Tor traffic in your PCAP!
	1. Run: `python classifier.py /path/to/pcap/file.pcap`
* Note that if you don't have "fping," you need to install it.
	* MacOS: `brew install fping`
	* Ubuntu: `apt-get install fping`
		* May need 'sudo' for Ubuntu installation

## Getting a PCAP
* If you just want to look at your own traffic going in and out of your computer, _tcpdump_ is a pretty good option
	1. If you are on MacOS, run: `tcpdump -i en0 -w /path/to/save/pcap/file.pcap`

# This is still a work in progress so comments, issues, suggestions, etc are 5sure welcomed!

## Detecting Bridge Nodes
* Note, this is still a work in progress and still produces a lot of false positives
* To detect bridge nodes, run:
	* `python find_bridge_nodes.py /path/to/pcap/file.pcap`
* Bridge nodes have IPs that are not listed on the known set of Tor IPs
* They are used in the case where censors (i.e. China) have blocked traffic to and from the known set of Tor IPs
* Currently, the pluggable transport Obfs4 is used to fully obfuscate all Tor traffic flowing from a client to a bridge node.
	* Packets are fully encrypted and the traffic looks like no normal protocol.
	* Accodring to Tor Documentation (https://blog.torproject.org/obfsproxy-next-step-censorship-arms-race), you can detect Obsf3 by running an entropy test on packets since the obfuscated bridge node traffic has higher entropy than typical network traffic
* Basically for packet sent to a specific server, the packet is converted into a bitstream and XOR’d with all other packets sent to that specific server.  The idea is that we should see a lot of 0s in the resulting XORs for normal data because a lot of packets are formatted the same (headers are very similar), but we should see a lot of 1s for bridge node traffic because all of the data is random.
* Current status: 
	* `find_bridge_nodes.py` returns a lot of false positives.  This script needs to change to just look at the client/server handshakes and not XOR any data packets.  Data packets are going to result in a lot of 1s for both bridge node and regular traffic.  Since data packets are factored into the current implementation, this won’t give us a great idea but at least gives us a starting point.


