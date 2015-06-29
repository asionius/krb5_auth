#ifndef _CONSTANTS_H_
#define _CONSTANTS_H_
#define HEAD_LEN sizeof(int)*5

#define VERSION 1
#define IS_ENCRYPT 0
#define MAGIC_WORD 1

#define DOMAIN_NAME	ABC.COM

/****start define packet type*****/
#define CLIENT_KRB5_AUTH_REQUEST 	0X00000001 //client send krb5 request
/*{head}*/
#define CLIENT_KRB5_AUTH_RESPONSE 	0X00000002 //server krb5 response
/*{head|int(res)}   0--success  1--failed*/
#define CLIENT_TOKEN_KEY_REQUEST 	0X00000003
/*{head}*/
#define CLIENT_TOKEN_KEY_RESPONSE 	0X00000004
/*{head|jsonstr({'access_token':,'refresh_token':'','enc_key':''})}*/

#define CLIENT_REFRESH_TOKEN_REQUEST	0X00000005
/*{head|json({'access_token':,'refresh_token':''})}*/
#define CLIENT_REFRESH_TOKEN_RESPONSE	0x00000006
/*{head|jsonstr({'access_token':,'refresh_token':'','enc_key':''})}*/

#define CLIENT_PACKET_TYPE_UNKNOWN	0X0000000F

/****end define packet type*****/
#endif
