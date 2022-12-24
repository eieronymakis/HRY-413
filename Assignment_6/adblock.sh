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

        echo "Processing domain names..."

        # Clear files from previous executions

        rm -rf commonDomains.txt
        rm -rf differentDomains.txt
        rm -rf $IPAddressesSame
        rm -rf $IPAddressesDifferent

        # Get lines in file2 not in file1
        join -v 1 <(sort $domainNames2) <(sort $domainNames) >> differentDomains.txt
        # Get lines in file1 not in file2
        join -v 2 <(sort $domainNames2) <(sort $domainNames) >> differentDomains.txt
        # Get common lines of file1 and file2
        grep -Fxf $domainNames $domainNames2> commonDomains.txt

        # Read common domains
        while read domain
        do
        dig_ret=$(dig +short "$domain")
        size=${#dig_ret} 
        #if the IP Address is empty or if there is a timeout don't append to file
        if [[ $dig_ret == *"timed out"* || $size == 0 ]] 
        then 
            continue
        else
            echo "${dig_ret}" >> IPAddressesSa.txt
        fi
        done < commonDomains.txt

        # Read different domains
        while read domain
        do
        dig_ret=$(dig +short "$domain")
        size=${#dig_ret} 
        if [[ $dig_ret == *"timed out"* || $size == 0 ]] 
        then 
            continue
        else
            echo "${dig_ret}" >> IPAddressesDiff.txt
        fi
        done < differentDomains.txt

        # Keep the unique IP Addresses in each file
        awk '{!seen[$0]++};END{for(i in seen) if(seen[i]>0)print i}' IPAddressesDiff.txt | sort >> IPAddressesDiffUniq.txt
        awk '{!seen[$0]++};END{for(i in seen) if(seen[i]>0)print i}' IPAddressesSa.txt | sort >> IPAddressesSaUniq.txt


        # Filter out everything that's not IP
        grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' IPAddressesDiffUniq.txt >> $IPAddressesDifferent
        grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' IPAddressesSaUniq.txt >> $IPAddressesSame
        
        # Remove files used for processing
        rm -rf IPAddressesDiff.txt
        rm -rf IPAddressesDiffUniq.txt
        rm -rf IPAddressesSa.txt
        rm -rf IPAddressesSaUniq.txt
        rm -rf commonDomains.txt
        rm -rf differentDomains.txt

        echo "--------------------------------------------------------------------"
        echo "Processing Completed! IP's were exported to the respective files..."
        echo "--------------------------------------------------------------------"

        true
            
    elif [ "$1" = "-ipssame"  ]; then
        # Configure the DROP adblock rule based on the IP addresses of $IPAddressesSame file.
        # Write your code here...
        # ...
        # ...
        while IFS= read line
        do
            iptables -A INPUT -s $line -j DROP

        done < $IPAddressesSame

        true
    elif [ "$1" = "-ipsdiff"  ]; then
        # Configure the REJECT adblock rule based on the IP addresses of $IPAddressesDifferent file.
        # Write your code here...
        # ...
        # ...
        while IFS= read line
        do
            iptables -A INPUT -s $line -j REJECT

        done < $IPAddressesDifferent

        true
        
    elif [ "$1" = "-save"  ]; then
        # Save rules to $adblockRules file.
        # Write your code here...
        # ...
        # ...
        iptables-save > $adblockRules
        true
        
    elif [ "$1" = "-load"  ]; then
        # Load rules from $adblockRules file.
        # Write your code here...
        # ...
        # ...
        iptables-restore < $adblockRules
        true

        
    elif [ "$1" = "-reset"  ]; then
        # Reset rules to default settings (i.e. accept all).
        # Write your code here...
        # ...
        # ...
        iptables -F
        true

        
    elif [ "$1" = "-list"  ]; then
        # List current rules.
        # Write your code here...
        # ...
        # ...
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
