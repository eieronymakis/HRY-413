#!/bin/bash

# You are NOT allowed to change the files' names!
domainNames="domainNames.txt"
domainNames2="domainNames2.txt"
IPAddressesSame="IPAddressesSame.txt"
IPAddressesDifferent="IPAddressesDifferent.txt"
adblockRules="adblockRules"

function adBlock() {
    if [ "$EUID" -ne 0 ];then
        printf "Please run as root.\n"
        exit 1
    fi
    if [ "$1" = "-domains"  ]; then

        # Remove temporary files used for processing
        rm -rf commonDomains.txt
        rm -rf differentDomains.txt
        rm -rf tmpIPsSame.txt
        rm -rf tmpIPsDiff.txt
        rm -rf tmpIPsSameUniq.txt
        rm -rf tmpIPsDiffUniq.txt

        echo "Processing domain names, this might take some time..."

        # grep options used : 
        # -F, Interpret PATTERNS as fixed strings, not regular expressions
        # -x, Select only those matches that exactly match the whole line
        # -f, Obtain patterns from FILE, one per line.
        # -v, Invert the sense of matching, to select non-matching lines.

        # Get lines in domainNames not in domainNames2 (lines are domains in our case)
        grep -Fxvf $domainNames $domainNames2 >> differentDomains.txt
        # Get lines in domainNames2 not in domainNames (lines are domains in our case)
        grep -Fxvf $domainNames2 $domainNames >> differentDomains.txt
        # Get common lines (domains) of file1 and file2
        grep -Fxf $domainNames $domainNames2> commonDomains.txt

        # dig options used :
        # -f, read from file
        # +short, short answer

        # perform DNS lookup for domains in domain files and export results to IP file
        dig +short -f commonDomains.txt >> tmpIPsSame.txt
        dig +short -f differentDomains.txt >> tmpIPsDiff.txt

        # awk loops through the lines and counts appearances then prints each unique,
        # then sort printed and export to file
        awk '{!seen[$0]++};END{for(i in seen) if(seen[i]>0)print i}' tmpIPsSame.txt | sort >> tmpIPsSameUniq.txt
        awk '{!seen[$0]++};END{for(i in seen) if(seen[i]>0)print i}' tmpIPsDiff.txt | sort >> tmpIPsDiffUniq.txt

        # Filter only IP's using grep and regex, then export them to file (filters out CNAME's, A records etc.)
        # iptables' souce/destination address arg expects ip's not domain names...
        grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' tmpIPsSameUniq.txt  >> $IPAddressesSame
        grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' tmpIPsDiffUniq.txt >> $IPAddressesDifferent
	
	echo "--------------------------------------------------------------------"
        echo "Processing Completed! IP's were exported to the respective files..."
        echo "--------------------------------------------------------------------"

        # Remove temporary files used for processing
        rm -rf commonDomains.txt
        rm -rf differentDomains.txt
        rm -rf tmpIPsSame.txt
        rm -rf tmpIPsDiff.txt
        rm -rf tmpIPsSameUniq.txt
        rm -rf tmpIPsDiffUniq.txt

        true
            
    elif [ "$1" = "-ipssame"  ]; then
        # Set DROP rule for each IP in IPAddressesSame.txt
        while IFS= read ip
        do
            iptables -A INPUT -s $ip -j DROP

        done < $IPAddressesSame
        true
    elif [ "$1" = "-ipsdiff"  ]; then
        # Set REJECT rule for each IP in IPAddressesDifferent.txt
        while IFS= read ip
        do
            iptables -A INPUT -s $ip -j REJECT

        done < $IPAddressesDifferent
        true
    elif [ "$1" = "-save"  ]; then
        # Export adblock rules to adblockRules file
        iptables-save > $adblockRules
        true
    elif [ "$1" = "-load"  ]; then
        # Load adblock rules from adblockRules file
        iptables-restore < $adblockRules
        true
    elif [ "$1" = "-reset"  ]; then
        # Reset IP tables rule set
        iptables -F
        true
    elif [ "$1" = "-list"  ]; then
        # List IP tables rules
        iptables --list -n -v
        true
    elif [ "$1" = "-help"  ]; then
        printf "This script is responsible for creating a simple adblock mechanism. It rejects connections from specific domain names or IP addresses using iptables.\n\n"
        printf "Usage: $0  [OPTION]\n\n"
        printf "Options:\n\n"
        printf "  -domains\t  Configure adblock rules based on the domain names of '$domainNames' file.\n"
        printf "  -ipssame\t\t  Configure the DROP adblock rule based on the IP addresses of $IPAddressesSame file.\n"
	printf "  -ipsdiff\t\t  Configure the DROP adblock rule based on the IP addresses of $IPAddressesDifferent file.\n"
        printf "  -save\t\t  Save rules to '$adblockRules' file.\n"
        printf "  -load\t\t  Load rules from '$adblockRules' file.\n"
        printf "  -list\t\t  List current rules.\n"
        printf "  -reset\t  Reset rules to default settings (i.e. accept all).\n"
        printf "  -help\t\t  Display this help and exit.\n"
        exit 0
    else
        printf "Wrong argument. Exiting...\n"
        exit 1
    fi
}

adBlock $1
exit 0
