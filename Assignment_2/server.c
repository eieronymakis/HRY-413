#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include "openssl/ssl.h"
#include "openssl/err.h"


/* Useful links I used */
/* https://wiki.openssl.org/index.php/Simple_TLS_Server */
/* https://man7.org/linux/man-pages/man2/connect.2.html */
/* https://www.gta.ufrj.br/ensino/eel878/sockets/sockaddr_inman.html */


// Create the SSL socket and intialize the socket address structure
int OpenListener(int port)
{
    /* The socket file descriptor */
    int sockfd;

    /* Transport address and port for the AF_INET address family */
    struct sockaddr_in addr;

    /* Clear memory of the address structure for every run of the server */
    /* If I don't clear the address struct data, then when a new connection happens data from previous connections result to an error*/
    memset(&addr, '\0', sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    /* Get the socket file descriptor */
    sockfd = socket(PF_INET, SOCK_STREAM, 0);

    if(sockfd < 0){
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }
    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }
    if ( listen(sockfd, 10) != 0 )
    {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }

    return sockfd;
}
int isRoot()
{
    if (getuid() != 0)
    {
        return 0;
    }
    else
    {
        return 1;
    }
}
SSL_CTX* InitServerCTX(void)
{
	/* load & register all cryptos, etc. */
    OpenSSL_add_all_algorithms();
	/* load all error messages */
    SSL_load_error_strings();
	/* create new server-method instance */
    const SSL_METHOD * method = TLS_server_method();
	/* create new context from method */
    SSL_CTX * ctx = SSL_CTX_new(method);
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{   
    /* Set the certificate */
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* Set private key */
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* Check private key given */
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}
void ShowCerts(SSL* ssl)
{
    /* My Self Signed Cert given through the server */
    X509 * cert = SSL_get_peer_certificate(ssl);
	/* Get certificates (if available) */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");

        char * line;
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);

        printf("Subject: %s\n", line);
        free(line);

        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
    }
    else
        printf("No certificates.\n");
}

void Servlet(SSL* ssl) /* Serve the connection -- threadable */
{
    char buf[1024] = {0};
    int sd, bytes;
    const char* ServerResponse="<\\Body>\
                               <Name>sousi.com</Name>\
                 <year>1.5</year>\
                 <BlogType>Embedede and c\\c++<\\BlogType>\
                 <Author>John Johny<Author>\
                 <\\Body>";
    const char *cpValidMessage = "<Body>\
                               <UserName>Sousi<UserName>\
                 <Password>123<Password>\
                 <\\Body>";
	/* do SSL-protocol accept */
    if(SSL_accept(ssl) == 1){
        /* Read the request */
        bytes = SSL_read(ssl, buf, sizeof(buf));
        buf[bytes] = '\0';
    
        printf("Client sent: \"%s\"\n", buf);

        if( bytes > 0 ){
            if( strcmp(cpValidMessage,buf) == 0){
                SSL_write(ssl, ServerResponse, strlen(ServerResponse));
            }else{
                SSL_write(ssl, "Invalid Message", strlen("Invalid Message"));
            }
        }
    }
    /*else print "Invalid Message" */
    else{
        printf("Invalid Message!\n");
    }
    
	/* get socket connection */
    sd = SSL_get_fd(ssl);
	/* release SSL state */
    SSL_free(ssl);
    /* close connection */
    close(sd);
}
int main(int count, char *Argc[])
{   
    /* Get port from command line arguments */
    char * port = Argc[1];
    //Only root user have the permsion to run the server
    if(!isRoot())
    {
        printf("This program must be run as root/sudo user!!");
        exit(0);
    }
    if ( count != 2 )
    {
        printf("Usage: %s <portnum>\n", Argc[0]);
        exit(0);
    }
    // Initialize the SSL library
    SSL_library_init();
    /* initialize SSL */
    SSL_CTX * ctx = InitServerCTX();
    /* load certs */
    LoadCertificates(ctx, "mycert.pem","mycert.pem");
    /* create server socket */
    int socket = OpenListener(atoi(port));
    while (1)
    {
        struct sockaddr_in address;
        socklen_t length = sizeof(address);
		/* accept connection as usual */
        int client = accept(socket, (struct sockaddr *)&address, &length);

        printf("Connection: %s:%d\n",inet_ntoa(address.sin_addr), ntohs(address.sin_port));
		/* get new SSL state with context */
        SSL * ssl = SSL_new(ctx);
		/* set connection socket to SSL state */
        SSL_set_fd(ssl, client);
		/* service connection */
        Servlet(ssl);
    }
	/* close server socket */
    close(socket);
	/* release context */
    SSL_CTX_free(ctx);
}
