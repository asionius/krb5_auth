/*
 * appl/sample/sserver/sserver.c
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * Sample Kerberos v5 server.
 *
 * sample_server:
 * A sample Kerberos server, which reads an AP_REQ from a TCP socket,
 * decodes it, and writes back the results (in ASCII) to the client.
 *
 * Usage:
 * sample_server servername
 *
 * file descriptor 0 (zero) should be a socket connected to the requesting
 * client (this will be correct if this server is started by inetd).
 */

#include "../../../include/k5-int.h"
#include "com_err.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <syslog.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "../sample.h"

extern krb5_deltat krb5_clockskew;

#ifndef GETPEERNAME_ARG3_TYPE
#define GETPEERNAME_ARG3_TYPE int
#endif

#define DEBUG

static void
usage(name)
    char *name;
{
	fprintf(stderr, "usage: %s [-p port] [-s service] [-S keytab]\n",
		name);
}	

int
main(argc, argv)
    int argc;
    char *argv[];
{
    krb5_context context;
    krb5_auth_context auth_context = NULL;
    krb5_ticket * ticket;
    struct sockaddr_in peername;
    GETPEERNAME_ARG3_TYPE  namelen = sizeof(peername);
    int sock = -1;			/* incoming connection fd */
    krb5_data recv_data;
    short xmitlen;
    krb5_error_code retval;
    krb5_principal server;
    char repbuf[BUFSIZ];
    char *cname;
    char *service = SAMPLE_SERVICE;
    short port = 0;		/* If user specifies port */
    extern int opterr, optind;
    extern char * optarg;
    int ch;
    krb5_keytab keytab = NULL;	/* Allow specification on command line */
    char *progname;
    int on = 1;

    progname = *argv;

    retval = krb5_init_context(&context);
    if (retval) {
	    com_err(argv[0], retval, "while initializing krb5");
	    exit(1);
    }

    /* open a log connection */
    openlog("sserver", 0, LOG_DAEMON);

    /*
     * Parse command line arguments
     *  
     */
    opterr = 0;
    while ((ch = getopt(argc, argv, "p:S:s:")) != -1)
    switch (ch) {
    case 'p':
	port = atoi(optarg);
	break;
    case 's':
	service = optarg;
	break;
    case 'S':
	if ((retval = krb5_kt_resolve(context, optarg, &keytab))) {
	    com_err(progname, retval,
		    "while resolving keytab file %s", optarg);
	    exit(2);
	}
	break;

      case '?':
    default:
	usage(progname);
	exit(1);
	break;
    }

    argc -= optind;
    argv += optind;

    /* Backwards compatibility, allow port to be specified at end */
    if (argc > 1) {
	    port = atoi(argv[1]);
    }

    retval = krb5_sname_to_principal(context, NULL, service, 
				     KRB5_NT_SRV_HST, &server);
    if (retval) {
	syslog(LOG_ERR, "while generating service name (%s): %s",
	       service, error_message(retval));
	exit(1);
    }
    
    /*
     * If user specified a port, then listen on that port; otherwise,
     * assume we've been started out of inetd. 
     */

    if (port) {
	int acc;
	struct sockaddr_in sockin;

	if ((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
	    syslog(LOG_ERR, "socket: %m");
	    exit(3);
	}
	/* Let the socket be reused right away */
	(void) setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&on,
			  sizeof(on));

	sockin.sin_family = AF_INET;
	//sockin.sin_addr.s_addr = 0;
	inet_pton(AF_INET, "10.3.36.20", &(sockin.sin_addr.s_addr));
	sockin.sin_port = htons(port);
	if (bind(sock, (struct sockaddr *) &sockin, sizeof(sockin))) {
	    syslog(LOG_ERR, "bind: %m");
	    exit(3);
	}
	if (listen(sock, 1) == -1) {
	    syslog(LOG_ERR, "listen: %m");
	    exit(3);
	}
	if ((acc = accept(sock, (struct sockaddr *)&peername, &namelen)) == -1){
	    syslog(LOG_ERR, "accept: %m");
	    exit(3);
	}
	dup2(acc, 0);
	close(sock);
	sock = 0;
    } else {
	/*
	 * To verify authenticity, we need to know the address of the
	 * client.
	 */
	if (getpeername(0, (struct sockaddr *)&peername, &namelen) < 0) {
	    syslog(LOG_ERR, "getpeername: %m");
	    exit(1);
	}
	sock = 0;
    }
#if 1
	size_t rlen = 0;
	char rbuf[1024];
	memset(rbuf, 0, 1024);
	rlen = recv(sock, rbuf, sizeof(rbuf), 0);
	
	if(rlen < 0)
	{
		printf("recv data error\n");
		return 1;
	} else if (rlen == 0)
	{
		printf("no data read\n");
		return 1;
	}

	if(send(sock, rbuf, rlen, 0) < 0)
	{
		printf("send data error\n");
		return 1;
	}

#endif 
    retval = krb5_recvauth(context, &auth_context, (krb5_pointer)&sock,
			   "1.0", server, 
			   0,	/* no flags */
			   keytab,	/* default keytab is NULL */
			   &ticket);
#if 1
	/* token test */
	memset(rbuf, 0, 1024);
	rlen = recv(sock, rbuf, sizeof(rbuf), 0);

	char response[1024] = {0};
	strcpy(response, "{\"result\":0, \"error_code\":0, \"token\":{\"access_token\":\"youmeiyounameyishougehuirangnituranxiangqiwo\", \"refresh_token\":\"youmeiyounameyishougehuirangnituranxiangqiwo\"," 
						"\"enc_key\":\"youmeiyounameyishougehuirangnituranxiangqiwo\"}}");
	int resLen = strlen(response);
	*(int*)(rbuf+4*sizeof(int)) = htonl(resLen);
	memcpy(rbuf+rlen, response, resLen);
	if(rlen < 0)
	{
		printf("recv data error\n");
		return 1;
	} else if (rlen == 0)
	{
		printf("no data read\n");
		return 1;
	}

	if(send(sock, rbuf, rlen+resLen, 0) < 0)
	{
		printf("send data error\n");
		return 1;
	}

	/* refresh token */
	memset(rbuf, 0, 1024);
	rlen = recv(sock, rbuf, sizeof(rbuf), 0);

	*(int*)(rbuf+4*sizeof(int)) = htonl(resLen);
	memcpy(rbuf+20, response, resLen);
	memset(rbuf+20+resLen, 0, 1);
	if(rlen < 0)
	{
		printf("recv data error\n");
		return 1;
	} else if (rlen == 0)
	{
		printf("no data read\n");
		return 1;
	}

	if(send(sock, rbuf, rlen+resLen, 0) < 0)
	{
		printf("send data error\n");
		return 1;
	}
#endif
    if (retval) {
	syslog(LOG_ERR, "recvauth failed--%s", error_message(retval));
	exit(1);
    }

    /* Get client name */
    repbuf[sizeof(repbuf) - 1] = '\0';
    retval = krb5_unparse_name(context, ticket->enc_part2->client, &cname);
    if (retval){
	syslog(LOG_ERR, "unparse failed: %s", error_message(retval));
	strncpy(repbuf, "You are <unparse error>\n", sizeof(repbuf) - 1);
    } else {
	strncpy(repbuf, "You are ", sizeof(repbuf) - 1);
	strncat(repbuf, cname, sizeof(repbuf) - 1 - strlen(repbuf));
	strncat(repbuf, "\n", sizeof(repbuf) - 1 - strlen(repbuf));
	free(cname);
    }
    xmitlen = htons(strlen(repbuf));
    recv_data.length = strlen(repbuf);
    recv_data.data = repbuf;
    if ((retval = krb5_net_write(context, 0, (char *)&xmitlen,
				 sizeof(xmitlen))) < 0) {
	syslog(LOG_ERR, "%m: while writing len to client");
	exit(1);
    }
    if ((retval = krb5_net_write(context, 0, (char *)recv_data.data,
				 recv_data.length)) < 0) {
	syslog(LOG_ERR, "%m: while writing data to client");
	exit(1);
    }

    krb5_free_ticket(context, ticket);
    if(keytab)
      krb5_kt_close(context, keytab);
    krb5_free_principal(context, server);
    krb5_auth_con_free(context, auth_context);
    krb5_free_context(context);
    exit(0);
}
