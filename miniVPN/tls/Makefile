all: 
	gcc -o tlsclient tlsclient.c -lssl -lcrypto 
	gcc -o tlsserver tlsserver.c -lssl -lcrypto 
	gcc -o vpnserver_tls vpnserver_tls.c -lssl -lcrypto -lcrypt
	gcc -o vpnserver_tls_multiclient vpnserver_tls_multiclient.c -lssl -lcrypto -lcrypt
	gcc -o vpnclient_tls vpnclient_tls.c -lssl -lcrypto
clean: 
	rm tlsclient tlsserver vpnserver_tls vpnclient_tls vpnserver_tls_multiclient

