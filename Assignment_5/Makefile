all:
	gcc pcap_ex.c -o pcap_ex -lpcap
clean:
	rm -rf pcap_ex
	rm -rf log.txt
live:
	./pcap_ex -i enp0s3
live_filtered:
	./pcap_ex -i enp0s3 -f "port 443"
offline:
	./pcap_ex -r test_pcap_5mins.pcap
offline_filtered:
	./pcap_ex -r test_pcap_5mins.pcap -f "port 443"
