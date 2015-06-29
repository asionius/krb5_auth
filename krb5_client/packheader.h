#ifndef _PACK_HEADER_H_
#define _PACK_HEADER_H_
#include "string.h"
#include <arpa/inet.h>

class PackHeader{
	public:
		int version;
		int isEncrypt;
		int magicword;
		int packType;
		int packLen;
		char *buf;
		PackHeader(char *head);
		PackHeader(int version, int isEncrypt, int magicword, int packTpe, int packLen);
		void getHeadFromBuf();
		void writeHeadToBuf();
		~PackHeader();
		void writeIntToBuf(char* &pack,int value);
		void getIntFromBuf(char* &pack,int *b);

};
#endif
