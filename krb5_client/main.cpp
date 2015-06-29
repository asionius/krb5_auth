#include <iostream>
#include "krb5auth.h"

using namespace std;
int main()
{
	const char* service = "host";
	const char* host = "win2k8";
	string token, key, refresh_token;
//	Krb5Auth myAuth(service, host);

	Krb5Auth *etcdAuth = Krb5Auth::getInstance(service, host);
	if(etcdAuth->krb5Init() != 0)
	{
		cout << "init failed" << endl;	
		return 1;
	}
	cout << "init sucess" << endl;	
	if(etcdAuth->krb5Connect() !=0)
	{
		cout << "connect failed" << endl;	
		return 1;
	}
	cout << "connect sucess" << endl;	

	if(etcdAuth->krb5Auth() != 0)
	{
		cout << "auth failed" << endl;	
		return 1;
	}
	cout << "auth success!" << endl;	

	if(etcdAuth->accessTokenAndKey(token, key, refresh_token) != 0)
	{
		cout << "acess token failed" << endl;
		return 1;
	}
	cout << "access token success!" << endl;	
	cout <<"token   " << token << endl;
	cout <<"key     " << key << endl;
	cout <<"refresh_token   " << refresh_token<< endl;
	if(etcdAuth->requestRefreshToken(token, key, refresh_token) != 0)
	{
		cout << "refresh token failed" << endl;
		return 1;
	}
	cout << "refresh token success!" << endl;	
	cout <<"token   " << token << endl;
	cout <<"key     " << key << endl;
	cout <<"refresh_token   " << refresh_token<< endl;

	return 0;
}
