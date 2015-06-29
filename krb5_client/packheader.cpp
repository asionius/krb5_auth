#include "packheader.h"
#include "packheaderException.h"

PackHeader::PackHeader(char *head)
{
	this->buf = head;
}

PackHeader::PackHeader(int version, int isEncrypt, int magicword,int packType, int packLen)
		:version(version),isEncrypt(isEncrypt),magicword(magicword),
		packType(packType),packLen(packLen)
{
#if 0
	this->version = version ;
	this->isEncrypt = isEncrypt;
	this->magicword = magicword;
	this->packType = packType;
	this->packLen = packLen;
#endif
}

PackHeader::~PackHeader()
{
}

void PackHeader::writeIntToBuf(char* &pack,int value)
{
	*(int*)pack=htonl(value);
	pack+=sizeof(int);
}

void PackHeader::getIntFromBuf(char* &pack,int *b)
{
	*b = ntohl(*((int *)pack));
        pack+=sizeof(int);
}

void PackHeader::getHeadFromBuf(){
	if(this->buf == NULL)
	{
		PackHeaderException *e = new PackHeaderException(1);
		throw e;
	}
	char *pack = this->buf;
	this->getIntFromBuf(pack,&(this->version));
	this->getIntFromBuf(pack,&(this->isEncrypt));
	this->getIntFromBuf(pack,&(this->magicword));
	this->getIntFromBuf(pack,&(this->packType));
	this->getIntFromBuf(pack,&(this->packLen));
}

void PackHeader::writeHeadToBuf()
{
	if(this->buf == NULL)
	{
		PackHeaderException *e = new PackHeaderException(1);
        throw e;
	}
	char *pack = this->buf;
	this->writeIntToBuf(pack,this->version);
	this->writeIntToBuf(pack,this->isEncrypt);
	this->writeIntToBuf(pack,this->magicword);
	this->writeIntToBuf(pack,this->packType);
	this->writeIntToBuf(pack,this->packLen);
}
