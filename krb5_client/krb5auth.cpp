#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <iostream>
#include <jsoncpp/json/json.h>
#include "krb5auth.h"
#include "constants.h"
#include "common.h"

#define BUF_LEN 1024
#define AUTH_VERSION "1.0"
#define TOKEN_LEN	48
using namespace std;

Krb5Auth* Krb5Auth:: instance = NULL;
Krb5Auth::Destruct Krb5Auth::destruct;
char buf[BUF_LEN] = {0};
Krb5Auth::Krb5Auth(const char* serviceName, const char* serviceHost)
    :auth_context(0),
	service(serviceName),
	host(serviceHost)
{}

Krb5Auth::~Krb5Auth()
{
	if(server) krb5_free_principal(context, server);		//finished using it
	if(client) krb5_free_principal(context, client);		
	if(ccdef) krb5_cc_close(context, ccdef);
    if (auth_context) krb5_auth_con_free(context, auth_context);
    krb5_free_context(context);
}

// return value:
// 0: success
// 1:failed
int Krb5Auth::krb5Init()
{
	int retval = 0;

    retval = krb5_init_context(&context);
	if(retval)
	{
		dlog("krb5Auth::krb5Init:error while initializing krb5\n");
		return 1;
	}

    (void) signal(SIGPIPE, SIG_IGN);

    retval = krb5_sname_to_principal(context, host, service,
				     KRB5_NT_SRV_HST, &server);
    if (retval)
	{
		dlog("krb5Auth::krb5Init:failed while creating server name for host %s service %s ret: %d\n",
		host, service, retval);
		return 1;
    }

    retval = krb5_cc_default(context, &ccdef);
    if (retval) {
		dlog("krb5Auth::krb5Init:failed while getting default ccache ret: %d\n", retval);
		return 1;
    }

    retval = krb5_cc_get_principal(context, ccdef, &client);
    if (retval) {
		dlog("while getting client principal name ret: %d\n", retval);
		return 1;
    }

    cksum_data.data = (char*)host;
    cksum_data.length = strlen(host);
	return 0;
}

// return values:
// 0: success
// other: failed 
int Krb5Auth::krb5Connect()
{
	char *portstr;
    int aierr;

	portstr = (char*)"2379";		//
    memset(&aihints, 0, sizeof(aihints));
    aihints.ai_socktype = SOCK_STREAM;
    aierr = getaddrinfo((char*)host, portstr, &aihints, &ap);
    if (aierr) {
		dlog("Krb5Auth::krb5Connect: error looking up host '%s' port '%s'/tcp: %s\n",
		(char*)host, portstr, gai_strerror(aierr));
		return -1;
    }

    if(-1 == (sock = socket(ap->ai_family, SOCK_STREAM,0)) )
    {
        dlog("krb5Auth::krb5Connect: error in create socket\n");
        return -1;
    }

#if 0
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port);
    dest_addr.sin_addr.s_addr = inet_addr(desIpAddr);
    memset(&dest_addr.sin_zero,0,8);
#endif

    if(connect(sock, ap->ai_addr, ap->ai_addrlen) < 0)
    {
        dlog("Krb5Auth::krb5Connect: connect error\n");
		close(sock);
		sock = -1;
        return -1;
    }
	return 0;
}

// parameter:
// requestType: the head auth type
// lenth: the body lenth to send
// return values:
// 0: success
// other: failed 
int Krb5Auth::krb5HeadAuth(int requestType, int lenth)
{
	head = new PackHeader(VERSION, IS_ENCRYPT, MAGIC_WORD, requestType, lenth);
	head->buf = buf;
	head->writeHeadToBuf();
	delete head;
	if(sock == -1)
	{
		dlog("Krb5Auth::krb5HeadAuth:sock closed!\n");
		return 1;
	}
	int iLen = send(sock, buf, HEAD_LEN + lenth, 0);	

	memset(buf, 0, BUF_LEN);
	iLen = recv(sock, buf, HEAD_LEN, 0);
	if(iLen < 0)
	{
		dlog("krb5Auth::krb5HeadAuth: recv error!\n");
		return 1;
	}else if(iLen == 0)
	{
		dlog("krb5Auth::krb5HeadAuth: recv nodata!\n");
		return 1;
	}

	if(iLen != HEAD_LEN)
	{
		dlog("krb5Auth::krb5HeadAuth: size invalid, recv other packet!\n");
		return 1;
	}
	head = new PackHeader(buf);
	head->getHeadFromBuf();
	if(head->packType == (requestType + 1))			
	//if(head->packType == requestType)
	{
#if 0
		if(head->packLen != 0)
		{
			memset(buf, 0, BUF_LEN);
			iLen = recv(sock, buf, head->packLen, 0);
			int res = -1;
			char *temp = buf;
			head->getIntFromBuf(temp,&res);
			dlog("Krb5Auth::krb5HeadAuth: get res is: %d\n", res);
		}
#endif
		dlog("Krb5Auth::krb5HeadAuth: res pack type: %d\n", head->packType);
	}
	else
	{
		dlog("Krb5Auth::krb5HeadAuth: res pack type: %d\n", head->packType);
		return 1;
	}
	return 0;
}

// return values:
// 0: success
// others: failed
int Krb5Auth::krb5Auth()
{
	int retval = 0;

	if(sock == -1)
	{
		dlog("Krb5Auth::krb5Auth:sock closed!\n");
		return 1;
	}
	if(krb5HeadAuth(CLIENT_KRB5_AUTH_REQUEST, 0) != 0)
	{
		dlog("Krb5Auth::krb5Auth:head auth failed\n");
		goto error;
	}

	if(head->packLen != 0)
	{
		recv(sock, head->buf, head->packLen, 0);		
	}

	retval = krb5_sendauth(context, &auth_context, (krb5_pointer)&sock, 
				(char*)AUTH_VERSION, client, server, 
				AP_OPTS_MUTUAL_REQUIRED, 
				&cksum_data, 
				NULL,			/* no creds, use ccache instead */
				ccdef, &err_ret, &rep_ret, NULL);
				
    if (retval && retval != KRB5_SENDAUTH_REJECTED) {
		dlog("Krb5Auth::krb5Auth: failed while using sendauth, ret: %d\n", retval);
		goto error;
    }
    if (retval == KRB5_SENDAUTH_REJECTED) {
		/* got an error */
		dlog("Krb5Auth::krb5Auth: sendauth rejected, error reply is:\n\t\"%*s\"\n",
	       err_ret->text.length, err_ret->text.data);
		goto error;
    } else if (rep_ret) {
		/* got a reply */
		krb5_free_ap_rep_enc_part(context, rep_ret);
		// read data from server
	} else {
		dlog("Krb5Auth::krb5Auth: no error or reply from sendauth!\n");
		goto error;
	}

	dlog("Krb5Auth::krb5Auth: auth success!\n");
	delete head;
	return 0;
error:
	delete head;
	return 1;
}


// return values:
// 0: success
// others: failed 
int Krb5Auth::accessTokenAndKey(std::string &token, std::string &key, std::string &refresh_token)
{
	int iLen;
	if(sock == -1)
	{
		dlog("Krb5Auth::accessToken:sock closed!\n");
		return 1;
	}
	memset(buf, 0, BUF_LEN);
	if(krb5HeadAuth(CLIENT_TOKEN_KEY_REQUEST, 0) != 0)
	{
		dlog("Krb5Auth::krb5Auth:head auth failed\n");
		goto error;
	}
	if(head->packLen != 0)
	{
		memset(head->buf, 0, BUF_LEN);
		iLen = recv(sock, head->buf, head->packLen, 0);
		if(iLen != head->packLen)
		{
			dlog("Krb5Auth::accessToken: recv other data\n");	
			goto error;
		} 
		dlog("Krb5Auth::accessToken: recv json: %s\n", head->buf);
		Json::Reader reader;
		Json::Value root;
		if(reader.parse(head->buf, root))
		{
			try {
				int ret = root["result"].asInt();
				if(ret != 0)
				{
					int error_code = root["error_code"].asInt();
					dlog("Krb5Auth::accessToken: access token error:%d\n", error_code);	
				}
				else 
				{
					Json::Value vToken = root["token"];
					token = vToken["access_token"].asString();
					refresh_token = vToken["refresh_token"].asString();	
					key = vToken["enc_key"].asString();
				}
			}
			catch(...)
			{
				dlog("Krb5Auth::accessToken: wrong json format\n");	
				goto error;
			}
		}
	}
	else
	{
		dlog("Krb5Auth::access_token: head recv error\n");
		goto error;
	}
	delete head;
	return 0;
error:
	delete head;
	return 1;
}

int Krb5Auth::requestRefreshToken(std::string &token, std::string &key, std::string &refresh_token)
{
	int iLen;
	if(sock == -1)
	{
		dlog("Krb5Auth::requestRefreshToken:sock closed!\n");
		return 1;
	}
	Json::Value root;
	root["access_token"] = token;
	root["refresh_token"] = refresh_token;
	string body = root.toStyledString();
	int bodyLen = strlen(body.c_str());
	memset(buf, 0, BUF_LEN);
	memcpy(buf+HEAD_LEN, body.c_str(), bodyLen);

	if(krb5HeadAuth(CLIENT_REFRESH_TOKEN_REQUEST, bodyLen) != 0)
	{
		dlog("Krb5Auth::requestRefreshToken:head auth failed\n");
		goto error;
	}
	if(head->packLen != 0)
	{
		memset(head->buf, 0, BUF_LEN);
		iLen = recv(sock, head->buf, head->packLen, 0);
		if(iLen != head->packLen)
		{
			dlog("Krb5Auth::requestRefreshToken: recv other data\n");	
			goto error;
		} 

		Json::Reader reader;
		Json::Value root;
		if(reader.parse(head->buf, root))
		{
			try {
				int ret = root["result"].asInt();
				if(ret != 0)
				{
					int error_code = root["error_code"].asInt();
					dlog("Krb5Auth::requestRefreshToken: access token error:%d\n", error_code);	
				}
				else 
				{
					Json::Value vToken = root["token"];
					token = vToken["access_token"].asString();
					refresh_token = vToken["refresh_token"].asString();	
					key = vToken["enc_key"].asString();
				}
			}
			catch(...) {
				dlog("Krb5Auth::requestRefreshToken: wrong json format\n");	
				goto error;
			}
		}
	}
	delete head;
	return 0;
error:
	delete head;
	return 1;
}

Krb5Auth* Krb5Auth::getInstance(const char* serviceName, const char* serviceHost)
{
	if(NULL == instance)
	{
		instance = new Krb5Auth(serviceName, serviceHost);
	}
	return instance;
}
void Krb5Auth::freeInstance()
{
	if(NULL != instance)
	{
		free(instance);
	}
}
