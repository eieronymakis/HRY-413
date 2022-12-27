---------------------------------------------------------
Emmanouil-Georgios Ieronymakis A.M. 2015030136
---------------------------------------------------------
Ubuntu 20.04.5 LTS
---------------------------------------------------------
Assignment 6
---------------------------------------------------------
In this Assignment I created a simple bash script which creates
firewall rules from given domain names using iptables and other linux commands.
---------------------------------------------------------
Implementation
---------------------------------------------------------
- domains option
---------------------------------------------------------
In the first step I separated the common domains from the different domains, using 
the grep command on the two domain files.

For both different and common domains I used dig command to resolve the IP address
of each domain.

I filtered out CNAME's, A records etc. from the IP files and kept only IP Addresses (using grep with regex),
that's because iptables expects IP's as source/destination arguments not domain names...
---------------------------------------------------------
Instruction file Questions
---------------------------------------------------------
1. After configuring the adblock rules test your script 
by visiting your favourite websites without 
any other adblocking mechanism (e.g., adblock browser extensions).
Can you see ads? Do they load? Some ads persist, why?
---------------------------------------------------------
Answer
---------------------------------------------------------
I mostly used https://d3ward.github.io/toolz/adblock to test out my Implementation.
I did manage to block most of the ads using domain names provided by this site,
and I saw the number of dropped, reject packets and bytes for every rule 
using the -list option.
Some ads still persisted but that happens due to the fact dns lookup for those domains
result to CNAME's, A records or nothing.
---------------------------------------------------------

