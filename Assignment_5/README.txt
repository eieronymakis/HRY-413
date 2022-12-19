-------------------------------------------------------------------------
Ieronymakis Emmanouil-Georgios A.M. 2015030136
-------------------------------------------------------------------------
- GCC version
-------------------------------------------------------------------------
gcc (Ubuntu 9.4.0-1ubuntu1~20.04.1) 9.4.0
-------------------------------------------------------------------------
What did I implement ?
-------------------------------------------------------------------------
Everything, but the retransmission recognition function findTcpRetransmission() doesn't give the exact same results as WireShark did.
-------------------------------------------------------------------------
- Description
-------------------------------------------------------------------------
I created a simple packet monitoring program using pcap library.

Firstly depending on the mode I use pcap_open_live (live mode) & pcap_open_offline (offline mode)
in order to start monitoring the packets from network interface or pcap file respectively.

Then I wrote the callback function for pcap loop which processes every packet.

At the start I count every packet, then I check if the IP Protocol(from IP Header) is an IPv4 or IPv6.
If the IP Protocol is not one of the above then the packet protocol is definetely not UDP or TCP,
because TCP and UDP run on top of IPv4 and IPv6.

I then calculate the IP header length and get source and destination addresses.

Then I extract the TCP header,UDP header from IP struct from which I get the source, destination ports.

If a filter was given I skip packets that don't meet the criteria.

I calculate the protocol payload and I print or log to file the packet details based on mode (live or offline) respectively.

I also check if the packet is a retransmission using the saved previous TCP Packets.

In the end I insert new network flows to the network flow array and print the statistics for this execution.
---------------------------------------------------------------------------
- Results
---------------------------------------------------------------------------
I compared my results to WireShark results and everything seems okay, except the Retransmission Detections in my code which doesn't give great results.
---------------------------------------------------------------------------
- Answers to exercise instruction document
---------------------------------------------------------------------------

11. Can you tell if an incoming TCP packet is a retransmission? If yes, how? If not, why?
Answer : 
There are multiple types of Retransmission but a basic retransmission happens when :
-> Packet is not keepalive
-> The next expected sequence number is greater then the current sequence number
I check both in findTcpRetransmission().

12. Can you tell if an incoming UDP packet is a retransmission? If yes, how? If not, why?
-> No. UDP doesn't use retransmissions because if the packet arrives and has a bad checksum then it's dropped.

---------------------------------------------------------------------------
Notes. Important!
---------------------------------------------------------------------------
I asked the assistants at the office hours about which port (source / destination) 
should I use if a filter is given and they told that I can use which ever I want,
I chose to use the source port.
Example:
If option -f "port 8080" is given the program will filter out packets that don't have 8080 source port.
Also I asked and made sure that only port can be given as a filter





