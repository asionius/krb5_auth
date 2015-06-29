#ifndef _KRB5AUTH_H
#define _KRB5AUTH_H

#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ctype.h>
#include <krb5.h>
#include <iostream>
#include "packheader.h" 

class Krb5Auth
{
public:
	static Krb5Auth* getInstance(const char* serviceName, const char* serviceHost);
	int krb5Init();
	int krb5Connect();
	int krb5HeadAuth(int requestType, int lenth);
	int krb5Auth();
	int accessTokenAndKey(std::string &token, std::string &key, std::string &refresh_token);
	int requestRefreshToken(std::string &token, std::string &key, std::string &refresh_token);
	void freeInstance();
private:
	static Krb5Auth *instance;
	Krb5Auth(const char* serviceName, const char* serviceHost);
	~Krb5Auth();
	int sock;
    struct addrinfo *ap, *apstart;
    struct addrinfo aihints;
	PackHeader *head;
	const char* service;
	const char* host;
	krb5_context context;
    krb5_principal client,server;
    krb5_ccache ccdef;
    krb5_data cksum_data;
    krb5_error_code retval;
    krb5_error *err_ret;
    krb5_ap_rep_enc_part *rep_ret;
    krb5_auth_context auth_context;
	class Destruct{
		public:
			~Destruct(){
				if(NULL != instance){
					delete instance;
					instance = NULL;
				}
			}
	};
	static Destruct destruct;
};

#endif
