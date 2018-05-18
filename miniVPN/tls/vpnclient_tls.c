#include <stdio.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>

/* include libraries from vpnclient.c */
#include <fcntl.h>
#include <unistd.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>

/* This header is to hide the password */
#include <termios.h>

/*This library is for handling ctrl+c signal and send terminate command to the server */
#include <signal.h>

#define BUFF_SIZE 2000
#define PORT_NUMBER 55555
#define SERVER_IP "10.0.2.7"


#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }
#define CA_DIR "ca_client" 

struct sockaddr_in peerAddr;

/* The below macros are for handling password input */
#define ENTER 13
#define TAB 9
#define BKSP 8

// made ssl a global variable so that termination is handled by the signhandler
SSL *ssl; 

void sendTerminateCommand() {
  char buff[BUFF_SIZE] = "terminate$$connection";
  buff[strlen(buff)] = '\0';
        
  if (ssl != NULL) {
     SSL_write(ssl, buff, BUFF_SIZE-1);
     SSL_shutdown(ssl);
     SSL_free(ssl);
  }
  exit(0);
}

void sigfun(int sig)
{
   printf("You have presses Ctrl-C command.. Terminating the connection\n");
   sendTerminateCommand();
}

int createTunDevice() {
   int tunfd;
   struct ifreq ifr;
   memset(&ifr, 0, sizeof(ifr));

   ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

   tunfd = open("/dev/net/tun", O_RDWR);
   ioctl(tunfd, TUNSETIFF, &ifr);

   return tunfd;
}

/*int connectToUDPServer(){
    int sockfd;
    char *hello="Hello";

    memset(&peerAddr, 0, sizeof(peerAddr));
    peerAddr.sin_family = AF_INET;
    peerAddr.sin_port = htons(PORT_NUMBER);
    peerAddr.sin_addr.s_addr = inet_addr(SERVER_IP);

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    // Send a hello message to "connect" with the VPN server
    sendto(sockfd, hello, strlen(hello), 0,
                (struct sockaddr *) &peerAddr, sizeof(peerAddr));

    return sockfd;
}*/

void tunSelected(int tunfd, int sockfd, SSL *ssl) {
    int  len;
    char buff[BUFF_SIZE];

//    printf("Got a packet from TUN\n");

    bzero(buff, BUFF_SIZE);
    len = read(tunfd, buff, BUFF_SIZE);
    buff[len] = '\0';
   /* sendto(sockfd, buff, len, 0, (struct sockaddr *) &peerAddr,
                    sizeof(peerAddr));*/
    SSL_write(ssl, buff, len);
}

void socketSelected(int tunfd, int sockfd, SSL* ssl) {
    int  len;
    int totalLen = 0;
    char buff[BUFF_SIZE];
    char *ptr = buff;
 //   printf("Got a packet from the tunnel\n");

    bzero(buff, BUFF_SIZE);
//    len = recvfrom(sockfd, buff, BUFF_SIZE, 0, NULL, NULL);
/*  do {
      len = SSL_read(ssl, ptr, sizeof(buff)-1);
      ptr += len;
      totalLen += len;
    } while (len > 0);*/
    len = SSL_read(ssl, buff, BUFF_SIZE);
    buff[len] = '\0';
//    printf("Buffer on tunnel is %s\n", buff);
    write(tunfd, buff, len);
}

int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    char  buf[300];

    X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    X509_NAME_oneline(X509_get_subject_name(cert), buf, 300);
    printf("subject= %s\n", buf);

    if (preverify_ok == 1) {
       printf("Verification passed.\n");
    } else {
       int err = X509_STORE_CTX_get_error(x509_ctx);
       printf("Verification failed: %s.\n",
                    X509_verify_cert_error_string(err));
       sendTerminateCommand();
    }
}

SSL* setupTLSClient(const char* hostname)
{
    // Step 0: OpenSSL library initialization 
   // This step is no longer needed as of version 1.1.0.
   SSL_library_init();
   SSL_load_error_strings();
   SSLeay_add_ssl_algorithms();

   SSL_METHOD *meth;
   SSL_CTX* ctx;
   SSL* ssl;

   meth = (SSL_METHOD *)TLSv1_2_method();
   ctx = SSL_CTX_new(meth);

  // SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
   SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
   if (SSL_CTX_load_verify_locations(ctx,NULL, CA_DIR) < 1) {
        printf("Error setting the verify locations. \n");
        exit(0);
   }
   ssl = SSL_new (ctx);

   X509_VERIFY_PARAM *vpm = SSL_get0_param(ssl); 
   X509_VERIFY_PARAM_set1_host(vpm, hostname, 0);

   return ssl;
}


int setupTCPClient(const char* hostname, int port)
{
   struct sockaddr_in server_addr;

   // Get the IP address from hostname
   struct hostent* hp = gethostbyname(hostname);

   // Create a TCP socket
   int sockfd= socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

   // Fill in the destination information (IP, port #, and family)
   memset (&server_addr, '\0', sizeof(server_addr));
   memcpy(&(server_addr.sin_addr.s_addr), hp->h_addr, hp->h_length);
//   server_addr.sin_addr.s_addr = inet_addr ("10.0.2.14"); 
   server_addr.sin_port   = htons (port);
   server_addr.sin_family = AF_INET;

   // Connect to the destination
   connect(sockfd, (struct sockaddr*) &server_addr,
           sizeof(server_addr));
   printf("TCP is established with the hostname IP: %s and port : %d\n", inet_ntoa(server_addr.sin_addr),
          port);
   return sockfd;
}

void performUserAuth(SSL *ssl) {
   char username[100];
   char ch;
   int i = 0;
   printf("Please enter your username:\n");
   scanf("%s", username);
  // this consumes the enter character
   getchar();
   char password[100];
   printf("Please enter your password:\n");
   
   struct termios oldt;
   struct termios newt;
   tcgetattr(STDIN_FILENO, &oldt);
   newt = oldt;
   newt.c_lflag &= ~(ICANON | ECHO );
   tcsetattr(STDIN_FILENO, TCSANOW, &newt);
   
   while (1) {
      ch = getchar();
      if (ch == '\n' || ch == '\t') {
        password[i] = '\0';
        printf("\n");
        break;
      } else if(ch == BKSP) {
	 if (i > 0) {
	   i--;
           printf("\b");  // for backspace
        }
      } else {
         password[i] = ch;
         i++;
         printf("*");   // replace character with backspace
      }
   }
   tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
  // printf("Password entered is: %s and len = %d\n", password, i);
   // send both the user name and password to the server to verify the user authentication;
   char sendBuff[BUFF_SIZE];
   bzero(sendBuff, BUFF_SIZE); 
   int sendlen = sprintf(sendBuff, "%s$%s", username,password);
   sendBuff[sendlen] = '\0';
   SSL_write(ssl, sendBuff, sendlen); 
   char recvBuff[BUFF_SIZE];
   bzero(recvBuff, BUFF_SIZE);
   int recvLen = SSL_read(ssl, recvBuff, BUFF_SIZE-1);
   recvBuff[recvLen] = '\0';
   if (strstr(recvBuff, "auth$ok") != NULL) {
     return;
   } else {
     printf("User authentication failed on the server side.. Terminating Connection\n");
     sendTerminateCommand();
   }
//   scanf("%s", password);
}


int main(int argc, char *argv[])
{
   int tunfd;
   tunfd  = createTunDevice();
   
   char *hostname = "yahoo.com";
   int port = 443;
   if (argc < 3) {
     printf("Usage: sudo ./vpnclient_tls <hostname> <port>\n");
     return 0;
   }
   
   if (argc > 1) hostname = argv[1];
   if (argc > 2) port = atoi(argv[2]);

   /*----------------TLS initialization ----------------*/
   ssl   = setupTLSClient(hostname);
   printf("TLSClientsetup initialisation is successful\n");

   /*----------------Create a TCP connection ---------------*/
   int sockfd = setupTCPClient(hostname, port);
   printf("TCPClientsetup is successful\n");

   /*----------------TLS handshake ---------------------*/
   SSL_set_fd(ssl, sockfd);
   printf("SSL_set_fd() is successful\n");
   int err = SSL_connect(ssl); CHK_SSL(err);
   printf("SSL connection is successful\n");
   printf("SSL connection using %s\n", SSL_get_cipher(ssl));
  
   signal(SIGINT, sigfun);
   performUserAuth(ssl);   

   /*----------------Send/Receive data --------------------*/
 /*  char buf[9000];
   char sendBuf[200];
   sprintf(sendBuf, "GET / HTTP/1.1\nHost: %s\n\n", hostname);
   SSL_write(ssl, sendBuf, strlen(sendBuf));

   int len;
   do {
     len = SSL_read (ssl, buf, sizeof(buf) - 1);
     buf[len] = '\0';
     printf("%s\n",buf);
   } while (len > 0);*/
   // Enter the main loop
   while (1) {
     fd_set readFDSet;

     FD_ZERO(&readFDSet);
     FD_SET(sockfd, &readFDSet);
     FD_SET(tunfd, &readFDSet);
     select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

     if (FD_ISSET(tunfd,  &readFDSet)) tunSelected(tunfd, sockfd, ssl);
     if (FD_ISSET(sockfd, &readFDSet)) socketSelected(tunfd, sockfd, ssl);
  }
}
