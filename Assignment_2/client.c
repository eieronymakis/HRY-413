#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

int OpenConnection(const char *hostname, int port)
{   
    /* Useful links */
    /* https://wiki.openssl.org/index.php/SSL/TLS_Client */
    /* https://man7.org/linux/man-pages/man2/connect.2.html */
    /* https://www.gta.ufrj.br/ensino/eel878/sockets/sockaddr_inman.html */

    /* The socket file descriptor */
    int sockfd;

    /* Transport address and port for the AF_INET address family */
    struct sockaddr_in addr;

    /* Clear memory of the address structure for every run of the server */
    /* If I don't clear the address struct data, then when a new connection happens data from previous connections result to an error*/
    memset(&addr, '\0', sizeof(addr));

    /* Set Address Family */
    addr.sin_family = AF_INET;
    /* Set the port */
    addr.sin_port = htons(port);
    /* Set host address */
    struct hostent * host = gethostbyname(hostname);
    addr.sin_addr.s_addr = * (long * ) (host -> h_addr);

    /* Get socket file descriptor */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    /* If the connection succeeds 0 is returned, if it fails -1 is returned */
    if(connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) == -1){
        close(sockfd);
        printf("OpenConnection() ERROR : Wrong hostname/port, check your arguments!\n");
        abort();
    }

    return sockfd;

}

SSL_CTX* InitCTX(void)
{
	/* Load cryptos, et.al. */
    OpenSSL_add_all_algorithms();
	/* Bring in and register error messages */
    SSL_load_error_strings();
	/* Create new client-method instance */
    const SSL_METHOD * method = TLS_client_method();
	/* Create new context */
    SSL_CTX * ctx = SSL_CTX_new(method);
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

void ShowCerts(SSL* ssl)
{   
    
    X509 * cert = SSL_get_peer_certificate(ssl);
	/* get the server's certificate */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        
        char * line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
       	free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);

        X509_free(cert);
    }
    else
        printf("Info: No client certificates configured.\n");
}
int main(int count, char *strings[])
{   
    /* Get Server host & port from command line arguments */
    char * host = strings[1];
    char * port = strings[2];

    /* Check if arguments are okay */
    if ( count != 3 )
    {
        printf("usage: %s <hostname> <portnum>\n", strings[0]);
        exit(0);
    }
    /* Initialize OpenSSL */
    SSL_library_init();
    /* Initialize Context */
    SSL_CTX * ctx = InitCTX();
    /* Call OpenConnection to connect to the socket */
    int sockfd = OpenConnection(host, atoi(port));
    /* create new SSL connection state */
    SSL * ssl = SSL_new(ctx);
	/* Attach the socket file descriptor returned from OpenConnection*/
    SSL_set_fd(ssl, sockfd);
	/* perform the connection */
    if ( SSL_connect(ssl) == -1 )
        ERR_print_errors_fp(stderr);
    else
    {
        char acUsername[16] = {0};
        char acPassword[16] = {0};

        /* The request structure */
        const char *cpRequestMessage = "<Body>\
                               <UserName>%s<UserName>\
                 <Password>%s<Password>\
                 <\\Body>";
        printf("Enter the User Name : ");
        scanf("%s",acUsername);
        printf("\nEnter the Password : ");
        scanf("%s",acPassword);
		
        /* construct reply */
        char clientRequest[1024] = {0};
        sprintf(clientRequest, cpRequestMessage, acUsername, acPassword);

        printf("\n\nConnected with %s encryption\n", SSL_get_cipher(ssl));
   		/* get any certs */
        ShowCerts(ssl);
        /* encrypt & send message */
        SSL_write(ssl, clientRequest, strlen(clientRequest));
        /* get reply & decrypt */
        char buf[1024];
        int bytes = SSL_read(ssl, buf, sizeof(buf));
        buf[bytes] = 0;
        printf("Received : \"%s\"\n", buf);
	    /* release connection state */
        SSL_free(ssl);
    }
	/* close socket */
    close(sockfd);
	/* release context */
    SSL_CTX_free(ctx);
    return 0;
}
