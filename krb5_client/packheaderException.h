#ifndef _PACK_HEADER_EXCEPTION_H_
#define _PACK_HEADER_EXCEPTION_H_
#include <iostream>
using namespace std;
class PackHeaderException
{
	public:
		int errno;
 		PackHeaderException(int errno){
			this->errno = errno ;
		}
};
#endif
