#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>
#include <linux/tcp.h>
#include <linux/udp.h>

/* Useful links */
// -> https://linux.die.net/man/3/pcap (pcap lib)
// -> https://www.liveaction.com/resources/white-papers-solution-briefs/packet-vs-flow-a-look-at-network-traffic-analysis-techniques/ (Netflows vs Packets)

/* Colors for stdout */
#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

/* Create true, false enum */
typedef enum { FALSE = 0, TRUE = !FALSE} bool;

/* Application Mode Variables */
bool OFFLINE = FALSE;
bool LIVE = FALSE;

/* Applicaion Variables */
char * INTERFACE_NAME = NULL;
char * PACKET_CAP_FILE_NAME = NULL;
int FILTER_SOURCE_PORT = -1;
bool HELP = FALSE;

/* Pcap globals */
pcap_t * CAP_HANDLE_DESC;
char ERROR_BUFFER[PCAP_ERRBUF_SIZE];
int READ_TIMEOUT_MS = 10000;

/* Statistics */
typedef struct{
    char * source_addr;
    char * dest_addr;
    int source_port;
    int dest_port;
    char protocol[4];
}flow;


/* Statistic Variables */
flow * netflows;

int PACKET_COUNT = 0;
int TCP_UDP_PACKET_COUNT = 0;

int TCP_PACKET_COUNT=0;
int UDP_PACKET_COUNT=0;

int NETFLOW_COUNT = 0;
int TCP_NETFLOW_COUNT=0;
int UDP_NETFLOW_COUNT=0;

int TCP_BYTES = 0;
int UDP_BYTES = 0;

/* Output file used in LIVE mode */
FILE * LOG_FILE = NULL;

/* Prints information about a packet (Used in Offline mode) */
void printPacket(int pc, char * saddr, char * daddr, unsigned short sport, unsigned short dport, char * prot, int hl, int pl){
    printf("{\n");
    printf("\t# : %d,\n",pc);
    printf("\tSource IP Address : %s,\n",saddr);
    printf("\tDestination IP Address : %s,\n",daddr);
    printf("\tSource Port Number : %hu,\n",sport);
    printf("\tDestination Port Number : %hu,\n",dport);
    printf("\tProtocol : %s,\n",prot);
    printf("\t%s header length : %d,\n",prot,hl);
    printf("\t%s payload length : %d\n",prot,pl);
    printf("}\n\n"); 
}

/* Check if the packet is a new Network flow, if yes then insert it to the netflow array */
void insertFlow(char * src, char * dst, unsigned short src_prt, unsigned short dst_prt, char * prot, int ipv){
    
    bool exists = FALSE;
    /* Check if there is a record sharing the same attributes */
    /* A network flow is defined by the 5-tuple {source IP address, source port, destination IP address, destination
port, protocol}. */
    for(int i = 0; i < NETFLOW_COUNT; i++){
        if(strcmp(netflows[i].source_addr,src)==0&&strcmp(netflows[i].dest_addr,dst)==0&&netflows[i].source_port==src_prt&&netflows[i].dest_port==dst_prt&&strcmp(netflows[i].protocol,prot)==0){
            exists = TRUE;
            break;
        }
    }   
    /* If there isn't this is a new netflow */
    if(!exists){
        netflows=realloc(netflows,(NETFLOW_COUNT+1)*sizeof(flow));
        if(ipv==4){
            netflows[NETFLOW_COUNT].source_addr=(char*)malloc(INET_ADDRSTRLEN);
            netflows[NETFLOW_COUNT].dest_addr=(char*)malloc(INET_ADDRSTRLEN);
        }
        else{
            netflows[NETFLOW_COUNT].source_addr=(char*)malloc(INET6_ADDRSTRLEN);
            netflows[NETFLOW_COUNT].dest_addr=(char*)malloc(INET6_ADDRSTRLEN);
        }

        /* Count Protocol Type Netflow */
        if(strcmp(prot, "TCP")==0)
            TCP_NETFLOW_COUNT++;else if
        (strcmp(prot,"UDP")==0)
            UDP_NETFLOW_COUNT++;

        strcpy(netflows[NETFLOW_COUNT].source_addr,src);
        strcpy(netflows[NETFLOW_COUNT].dest_addr,dst);
        netflows[NETFLOW_COUNT].source_port=(int)src_prt;
        netflows[NETFLOW_COUNT].dest_port=(int)dst_prt;
        strcpy(netflows[NETFLOW_COUNT].protocol,prot);

        NETFLOW_COUNT++;
    }
}

/* Callback function of pcap_open_live() & pcap_open_offline() used for packet processing*/
void callback(u_char * args, const struct pcap_pkthdr * pkthdr, const u_char * packet){

    PACKET_COUNT++;

    struct ether_header * ethHeaderPtr;
    ethHeaderPtr = (struct ether_header *) packet;

    uint16_t ether_type = ntohs(ethHeaderPtr->ether_type);

    /* Check if IPv4/IPv6 (If not then definitely not TCP/UDP) */
    if(ether_type != ETHERTYPE_IP && ether_type != ETHERTYPE_IPV6)
        return;

	/* IPv4 Header */
	struct ip* ipHeader = (struct ip*)(packet+sizeof(struct ether_header));
	/* IPv6 Header */
	struct ip6_hdr* ip6Header = (struct ip6_hdr*)(packet+sizeof(struct ether_header));
	
	int header_len;
	uint8_t packet_type;

    /* For IPv4 */
	if(ipHeader->ip_v==4)
        packet_type = ipHeader->ip_p;
    /* For IPv6 */
	else if(ipHeader->ip_v==6)
		packet_type = ip6Header->ip6_ctlun.ip6_un1.ip6_un1_nxt;
	
    /* IP header has (n blocks * 4) bytes length usually 20 bytes*/
	header_len = ipHeader->ip_hl*4;

    /* 5. Skip any packet that is not TCP or UDP. */
	if(packet_type!=IPPROTO_TCP && packet_type!=IPPROTO_UDP)
		return;

    int af;

	if(ipHeader->ip_v == 4)
        af = AF_INET;
    else
        af = AF_INET6;
    
	char source_addr[INET6_ADDRSTRLEN];
	char dest_addr[INET6_ADDRSTRLEN];
	inet_ntop(af, &(ipHeader->ip_src), source_addr, sizeof(source_addr));
	inet_ntop(af, &(ipHeader->ip_dst), dest_addr, sizeof(dest_addr));
    
	struct tcphdr* tcpHeader = (struct tcphdr*)(sizeof(struct ip)+sizeof(struct ether_header)+packet);
	struct udphdr* udpHeader = (struct udphdr*)(sizeof(struct ip)+sizeof(struct ether_header)+packet);

	unsigned short source_port;
	unsigned short dest_port;
	unsigned int protocol_header_length;
    char protocol_type_string[4];

    /* if TCP */
	if(packet_type == IPPROTO_TCP){
		source_port = ntohs(tcpHeader->source);
		dest_port = ntohs(tcpHeader->dest);
		protocol_header_length=tcpHeader->doff*4;
        strcpy(protocol_type_string,"TCP");
    /* if UDP */
	}else if(packet_type == IPPROTO_UDP){
		source_port = ntohs(udpHeader->source);
		dest_port = ntohs(udpHeader->dest);
        /* UDP header has a fixed length of 8 bytes */
		protocol_header_length = 8;
        strcpy(protocol_type_string,"UDP");
	}

    /* Filtering with Source Port (doesn't affect unfiltered execution) */
    if(FILTER_SOURCE_PORT > 0 && source_port != FILTER_SOURCE_PORT)
        return;

    TCP_UDP_PACKET_COUNT++;

    int payload_length = pkthdr -> caplen - sizeof(struct ether_header) - header_len - protocol_header_length;

    /* Offline mode */
    if(OFFLINE)
        printPacket(PACKET_COUNT,source_addr,dest_addr,source_port,dest_port,protocol_type_string,protocol_header_length,payload_length);  
    /* Live mode */
    else if(LIVE)
        fprintf(LOG_FILE,"{\n\t# : %d,\n\tSource Addr. : %s,\n\tDest. Addr. : %s,\n\tSource Port : %hu,\n\tDest. Port : %hu,\n\tProtocol : %s,\n\tProt. Header Length : %d,\n\tProt. Payload Length : %d\n}\n", PACKET_COUNT, source_addr, dest_addr, source_port, dest_port, protocol_type_string,protocol_header_length, payload_length);


    insertFlow(source_addr,dest_addr,source_port,dest_port,protocol_type_string,ipHeader->ip_v);

    if(strcmp(protocol_type_string,"TCP") == 0){
        TCP_PACKET_COUNT++;
        TCP_BYTES+=payload_length;
    }else{
        UDP_PACKET_COUNT++;
        UDP_BYTES+=payload_length;
    }
}

/* Set callback function and loop through packets */
void initiatePcapLoop(){
    pcap_loop(CAP_HANDLE_DESC, 0, callback, NULL);
}

/* Not working */
void terminatePcapLoop(int num){
    pcap_breakloop(CAP_HANDLE_DESC);
}

/* Prints the necessary help information */
void help(){
        printf(ANSI_COLOR_GREEN"________________________________________\n");
        printf("Options (arguments)\n");
        printf("________________________________________\n");
        printf("-i filename\tType an interface name to monitor traffic\t(e.g., eth0)\n");
        printf("-r filename\tType a pcap file name to monitor traffic\t(e.g., test.pcap)\n");
        printf("-f expression\tType a filter expression to use\t\t\t(e.g., port 8080)\n");
        printf("________________________________________\n");
        printf("Example Usage\n");
        printf("________________________________________\n");
        printf("./pcap_ex -i eth0\n");
        printf("./pcap_ex -r test_pcap_5mins.pcap\n");
        printf("./pcap_ex -i eth0 -f \"port 8080\"\n");
        printf("./pcap_ex -r test_pcap_5mins.pcap -f \"port 8080\"\n");
        printf("________________________________________\n"ANSI_COLOR_RESET);
}

/* Processes command line arguments and options */
void processArgs(){
    if(INTERFACE_NAME != NULL && PACKET_CAP_FILE_NAME == NULL && HELP == FALSE){
        CAP_HANDLE_DESC = pcap_open_live(INTERFACE_NAME, BUFSIZ, FALSE, READ_TIMEOUT_MS, ERROR_BUFFER);
        if(CAP_HANDLE_DESC == NULL){
            printf("%s\n",ERROR_BUFFER);
            printf(ANSI_COLOR_RED"________________________________________\n");
            printf("Error @ Capture Handle Descriptor (Live)\n");
            printf("________________________________________\n"ANSI_COLOR_RESET);
            exit(-1);
        }
        LIVE = TRUE;
        LOG_FILE = fopen("log.txt", "a+");
        if(LOG_FILE == NULL){
            printf(ANSI_COLOR_RED"________________________________________\n");
            printf("Error : Can't open Log File (Live)\n");
            printf("________________________________________\n"ANSI_COLOR_RESET);
            exit(-1);
        }
    }else if(PACKET_CAP_FILE_NAME != NULL && INTERFACE_NAME == NULL && HELP == FALSE){
        CAP_HANDLE_DESC = pcap_open_offline(PACKET_CAP_FILE_NAME, ERROR_BUFFER);
        if(CAP_HANDLE_DESC == NULL){
            printf(ANSI_COLOR_RED"________________________________________\n");
            printf("Error @ Capture Handle Descriptor (Offline)\n");
            printf("________________________________________\n"ANSI_COLOR_RESET);
            exit(-1);
        }
        OFFLINE = TRUE;
    }else if(HELP==TRUE && INTERFACE_NAME == NULL && PACKET_CAP_FILE_NAME == NULL && FILTER_SOURCE_PORT == -1){
        help();
        exit(0);
    }else{
        printf(ANSI_COLOR_RED"________________________________________\n");
        printf("Run ./pcap_ex -h for help\n");
        printf("________________________________________\n"ANSI_COLOR_RESET);
        exit(-1);
    }

    initiatePcapLoop();
}

int main(int argc, char * argv[]){
    if(argc == 1){
        printf(ANSI_COLOR_RED"________________________________________\n");
        printf("Not enough options provided\n");
        printf("________________________________________\n"ANSI_COLOR_RESET);
        exit(-1);
    }

    char * expression;

    int opt;
    while((opt=getopt(argc,argv,"i:r:f:h")) != -1){
        switch(opt){
            case 'i':
                INTERFACE_NAME = strdup(optarg);
                break;
            case 'r':
                PACKET_CAP_FILE_NAME = strdup(optarg);
                break;
            case 'f':
                expression = strdup(optarg);
                char * token = strtok(expression, " ");
                FILTER_SOURCE_PORT = atoi(strtok(NULL, " "));
                if(FILTER_SOURCE_PORT <= 0){
                    printf(ANSI_COLOR_RED"________________________________________\n");
                    printf("Invalid Port given in option -f\n");
                    printf("________________________________________\n"ANSI_COLOR_RESET);
                    exit(-1);
                }
                break;
            case 'h':
                HELP = TRUE;
                break;
            default:
                exit(0);
        }
    }

    /* Choose action based on arguments */
    processArgs();

    /* What happens on user interrupt (not working needs while here) */
    signal(SIGINT, terminatePcapLoop);

    /* Done! Prints Statistics */
    printf(ANSI_COLOR_GREEN"________________________________________\n");
    printf("Statistics\n");
    printf("________________________________________\n"ANSI_COLOR_RESET);
    printf(ANSI_COLOR_GREEN"Network flows : %d\n",NETFLOW_COUNT);
    printf("TCP Network flows : %d\n",TCP_NETFLOW_COUNT);
    printf("UDP Network flows : %d\n",UDP_NETFLOW_COUNT);
    printf("Total Packets : %d\n",PACKET_COUNT);
    printf("TCP Packets : %d\n",TCP_PACKET_COUNT);
    printf("UDP Packets : %d\n",UDP_PACKET_COUNT);
    printf("TCP Packet Byte Count : %d\n", TCP_BYTES);
    printf("UDP Packet Byte Count : %d\n"ANSI_COLOR_RESET, UDP_BYTES);
    printf(ANSI_COLOR_GREEN"________________________________________\n\n"ANSI_COLOR_RESET);


    pcap_close(CAP_HANDLE_DESC);
    free(netflows);
    if(LIVE)
        fclose(LOG_FILE);

    return 0;
}