/*
 * Copyright (C) 2000,2001,2002,2003 Nikos Mavroyanopoulos
 * Copyright (C) 2004 Free Software Foundation
 *
 * This file is part of GNUTLS.
 *
 * GNUTLS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUTLS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <config.h>

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/extra.h>
#include <gnutls/x509.h>
#include <sys/time.h>
#include <pthread.h>
#include "common.h"
#include "cli-gaa.h"

#ifndef SHUT_WR
# define SHUT_WR 1
#endif

#ifndef SHUT_RDWR
# define SHUT_RDWR 2
#endif

#define SA struct sockaddr
#define ERR(err,s) do { if (err==-1) {perror(s);return(1);} } while (0)
#define MAX_BUF 4096

// needed for threading:
GCRY_THREAD_OPTION_PTHREAD_IMPL;

/* global stuff here */
int starttls;
char *hostname = NULL;
int port;
int record_max_size;
int fingerprint;
int crlf;
int quiet = 0;
extern int xml;
extern int print_cert;

char *x509_keyfile;
char *x509_certfile;
char *x509_cafile;
char *x509_crlfile = NULL;
static int x509ctype;
static int debug;

static gnutls_certificate_credentials xcred;

struct hostent *server_host;
extern pthread_mutex_t aMutex;

/* end of global stuff */

/* prototypes */
typedef struct {
	int fd;
	gnutls_session session;
	int secure;
	const char* hostname;
} socket_st;

ssize_t socket_recv(socket_st socket, void *buffer, int buffer_size);
ssize_t socket_send(socket_st socket, const void *buffer, int buffer_size);
void socket_bye(socket_st * socket);
static void check_rehandshake(socket_st socket, int ret);
static int do_handshake(socket_st * socket);
static void init_global_tls_stuff(void);


#undef MAX
#define MAX(X,Y) (X >= Y ? X : Y);

/* A callback function to be used at the certificate selection time.
 */
static int cert_callback(gnutls_session session,
			 const gnutls_datum * client_certs,
			 int client_certs_num,
			 const gnutls_datum * req_ca_rdn, int nreqs)
{
	char issuer_dn[256];
	int i, ret;
	size_t len;

	/* Print the server's trusted CAs
	 */
	if (nreqs > 0)
		printf("- Server's trusted authorities (%d):\n", nreqs);
	else
		printf
		    ("- Server did not send us any trusted authorities names.\n");

	/* print the names (if any) */
	for (i = 0; i < nreqs; i++) {
		len = sizeof(issuer_dn);
		ret = gnutls_x509_rdn_get(&req_ca_rdn[i], issuer_dn, &len);
		if (ret >= 0) {
			printf("   [%d]: ", i);
			printf("%s\n", issuer_dn);
		}
	}

	if (client_certs_num > 0)
		return 0;	/* use the first one */

	return -1;

}


/* initializes a gnutls_session with some defaults.
 */
static gnutls_session init_tls_session(const char *hostname)
{
	gnutls_session session;

	gnutls_init(&session, GNUTLS_CLIENT);

	gnutls_set_default_priority (session);

	gnutls_dh_set_prime_bits(session, 512);

	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);

	return session;
}

static void gaa_parser(int argc, char **argv);

/* Returns zero if the error code was successfully handled.
 */
static int handle_error(socket_st hd, int err)
{
	int alert, ret;
	const char *err_type, *str;

	if (err >= 0) return 0;

	if (gnutls_error_is_fatal(err) == 0) {
		ret = 0;
		err_type = "Non fatal";
	} else {
		ret = err;
		err_type = "Fatal";
	}

	str = gnutls_strerror(err);
	if (str == NULL) str = str_unknown;
	fprintf(stderr,
		"*** %s error: %s\n", err_type, str);

	if (err == GNUTLS_E_WARNING_ALERT_RECEIVED
	    || err == GNUTLS_E_FATAL_ALERT_RECEIVED) {
		alert = gnutls_alert_get(hd.session);
		str = gnutls_alert_get_name(alert);
		if (str == NULL) str = str_unknown;
		printf("*** Received alert [%d]: %s\n", alert, str);

		/* In SRP if the alert is MISSING_SRP_USERNAME,
		 * we should read the username/password and
		 * call gnutls_handshake(). This is not implemented
		 * here.
		 */
	}

	check_rehandshake(hd, ret);

	return ret;
}

int starttls_alarmed = 0;

void starttls_alarm (int signum)
{
  starttls_alarmed = 1;
}

int run()
{
	int err, ret;
	int sd, ii, i;
	struct sockaddr_in sa;
	char buffer[MAX_BUF + 1];
	char *session_data = NULL;
	char *session_id = NULL;
	int session_data_size;
	int session_id_size;
	fd_set rset;
	int maxfd;
	struct timeval tv;
	int user_term = 0;
	socket_st hd;

	sd = socket(AF_INET, SOCK_STREAM, 0);
	ERR(sd, "socket");

	memset(&sa, '\0', sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);

	sa.sin_addr.s_addr = *((unsigned int *) server_host->h_addr);

	if (inet_ntop(AF_INET, &sa.sin_addr, buffer, MAX_BUF) == NULL) {
		perror("inet_ntop()");
		return(1);
	}
	fprintf(stderr, "Connecting to '%s:%d'...\n", buffer, port);

	err = connect(sd, (SA *) & sa, sizeof(sa));
	ERR(err, "connect");

	hd.secure = 0;
	hd.fd = sd;
	hd.hostname = hostname;

	hd.session = init_tls_session(hostname);
	if (starttls)
		goto after_handshake;

	for (i = 0; i < 2; i++) {


		if (i == 1) {
			hd.session = init_tls_session(hostname);
			gnutls_session_set_data(hd.session, session_data,
						session_data_size);
			free(session_data);
		}

		ret = do_handshake(&hd);

		if (ret < 0) {
			fprintf(stderr, "*** Handshake has failed\n");
			gnutls_perror(ret);
			gnutls_deinit(hd.session);
			return 1;
		} else {
			printf("- Handshake was completed\n");
		}


		break;
	}


      after_handshake:

	{
		char* request = "GET / HTTP/1.0\r\n\r\n";
		ret = socket_send(hd, request, strlen(request));
	}

#ifndef _WIN32
	signal (SIGALRM, &starttls_alarm);
#endif

	/* do not buffer */
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);

	for (;;) {
		FD_ZERO(&rset);
		FD_SET(fileno(stdin), &rset);
		FD_SET(sd, &rset);

		maxfd = MAX(fileno(stdin), sd);
		tv.tv_sec = 3;
		tv.tv_usec = 0;
		err = select(maxfd + 1, &rset, NULL, NULL, &tv);

		if (err < 0) {
		  if (errno == EINTR && starttls_alarmed) {
		    if (hd.secure == 0) {
		      fprintf(stderr,
			      "*** Starting TLS handshake\n");
		      ret = do_handshake(&hd);
		      if (ret < 0) {
			fprintf(stderr,
				"*** Handshake has failed\n");
			socket_bye(&hd);
			user_term = 1;
		      }
		    } else {
		      user_term = 1;
		    }
		  }
		  continue;
		}

		if (FD_ISSET(sd, &rset)) {
			memset(buffer, 0, MAX_BUF + 1);
			ret = socket_recv(hd, buffer, MAX_BUF);

			if (ret == 0) {
				printf
				    ("- Peer has closed the GNUTLS connection\n");
				break;
			} else if (handle_error(hd, ret) < 0
				   && user_term == 0) {
				fprintf(stderr,
					"*** Server has terminated the connection abnormally.\n");
				break;
			} else if (ret > 0) {
				if (quiet != 0)
					printf("- Received[%d]: ", ret);
				for (ii = 0; ii < ret; ii++) {
					fputc(buffer[ii], stdout);
				}
				fflush(stdout);
			}

			if (user_term != 0)
				break;
		}
	}

	if (user_term != 0)
		socket_bye(&hd);


	return 0;
}

int main(int argc, char** argv)
{

	gaa_parser(argc, argv);
	if (hostname == NULL) {
		fprintf(stderr, "No hostname given\n");
		exit(1);
	}
	
	sockets_init();

#ifndef _WIN32
	signal(SIGPIPE, SIG_IGN);
#endif

	init_global_tls_stuff();


	printf("Resolving '%s'...\n", hostname);
	/* get server name */
	server_host = gethostbyname(hostname);
	if (server_host == NULL) {
		fprintf(stderr, "Cannot resolve %s\n", hostname);
		exit(1);
	}	

	pthread_mutex_init(&aMutex, NULL);

	// create and run threads
	const int NUM_THREADS = 4;
	pthread_t threads[NUM_THREADS];
	int result[NUM_THREADS];
	int i;
	for(i = 0; i < NUM_THREADS; ++i) {
		pthread_create(&threads[i], NULL, run, (void*) &result[i]);
	}

	// wait for all threads
	for(i = 0; i < NUM_THREADS; ++i) {
		pthread_join(threads[i], NULL);
	}

	fprintf(stderr, "all done\n");

	gnutls_certificate_free_credentials(xcred);

	gnutls_global_deinit();
}

static gaainfo info;
void gaa_parser(int argc, char **argv)
{
	if (gaa(argc, argv, &info) != -1) {
		fprintf(stderr,
			"Error in the arguments. Use the --help or -h parameters to get more information.\n");
		exit(1);
	}

	debug = info.debug;
	xml = info.xml;
	print_cert = info.print_cert;
	starttls = info.starttls;
	port = info.port;
	record_max_size = info.record_size;
	fingerprint = info.fingerprint;

	if (info.fmtder == 0)
		x509ctype = GNUTLS_X509_FMT_PEM;
	else
		x509ctype = GNUTLS_X509_FMT_DER;

	x509_cafile = info.x509_cafile;
	x509_crlfile = info.x509_crlfile;
	x509_keyfile = info.x509_keyfile;
	x509_certfile = info.x509_certfile;

	crlf = info.crlf;

	if (info.rest_args == NULL)
		hostname = "localhost";
	else
		hostname = info.rest_args;
}

void cli_version(void)
{
	fprintf(stderr, "GNU TLS test client, ");
	fprintf(stderr, "version %s. Libgnutls %s.\n", LIBGNUTLS_VERSION,
		gnutls_check_version(NULL));
}



/* Functions to manipulate sockets
 */

ssize_t socket_recv(socket_st socket, void *buffer, int buffer_size)
{
	int ret;

	if (socket.secure)
		do {
			ret =
			    gnutls_record_recv(socket.session, buffer,
					       buffer_size);
		} while (ret == GNUTLS_E_INTERRUPTED
			 || ret == GNUTLS_E_AGAIN);
	else
		do {
			ret = recv(socket.fd, buffer, buffer_size, 0);
		} while (ret == -1 && errno == EINTR);

	return ret;
}

ssize_t socket_send(socket_st socket, const void *buffer, int buffer_size)
{
	int ret;

	if (socket.secure)
		do {
			ret =
			    gnutls_record_send(socket.session, buffer,
					       buffer_size);
		} while (ret == GNUTLS_E_AGAIN
			 || ret == GNUTLS_E_INTERRUPTED);
	else
		do {
			ret = send(socket.fd, buffer, buffer_size, 0);
		} while (ret == -1 && errno == EINTR);

	if (ret > 0 && ret != buffer_size && quiet)
		fprintf(stderr,
			"*** Only sent %d bytes instead of %d.\n", ret, buffer_size);

	return ret;
}

void socket_bye(socket_st * socket)
{
	int ret;
	if (socket->secure) {
		do
			ret =
			    gnutls_bye(socket->session, GNUTLS_SHUT_RDWR);
		while (ret == GNUTLS_E_INTERRUPTED
		       || ret == GNUTLS_E_AGAIN);
		if (ret < 0)
			fprintf(stderr, "*** gnutls_bye() error: %s\n", gnutls_strerror(ret));
		gnutls_deinit(socket->session);
		socket->session = NULL;
	}

	shutdown(socket->fd, SHUT_RDWR);	/* no more receptions */
	close(socket->fd);

	socket->fd = -1;
	socket->secure = 0;
}

static void check_rehandshake(socket_st socket, int ret)
{
	if (socket.secure && ret == GNUTLS_E_REHANDSHAKE) {
		/* There is a race condition here. If application
		 * data is sent after the rehandshake request,
		 * the server thinks we ignored his request.
		 * This is a bad design of this client.
		 */
		printf("*** Received rehandshake request\n");
		/* gnutls_alert_send( session, GNUTLS_AL_WARNING, GNUTLS_A_NO_RENEGOTIATION); */

		ret = do_handshake(&socket);

		if (ret == 0) {
			printf("*** Rehandshake was performed.\n");
		} else {
			printf("*** Rehandshake Failed.\n");
		}
	}
}


static int do_handshake(socket_st * socket)
{
	int ret;
	gnutls_transport_set_ptr(socket->session,
				 (gnutls_transport_ptr) socket->fd);
	do {
		ret = gnutls_handshake(socket->session);

		if (ret < 0) {
			handle_error(*socket, ret);
		}
	} while (ret < 0 && gnutls_error_is_fatal(ret) == 0);

	if (ret == 0) {
		socket->secure = 1;
		/* print some information */
		print_info(socket->session, socket->hostname);
	}
	return ret;
}

static void tls_log_func(int level, const char *str)
{
	fprintf(stderr, "|<%d>| %s", level, str);
}

static void init_global_tls_stuff(void)
{
	int ret;

	if ((ret=gnutls_global_init()) < 0) {
		fprintf(stderr, "global_init: %s\n", gnutls_strerror(ret));
		exit(1);
	}

	gnutls_global_set_log_function(tls_log_func);
	gnutls_global_set_log_level(debug);

	if ((ret=gnutls_global_init_extra()) < 0) {
		fprintf(stderr,
			"global_init_extra: %s\n", gnutls_strerror(ret));
		exit(1);
	}

	/* X509 stuff */
	if (gnutls_certificate_allocate_credentials(&xcred) < 0) {
		fprintf(stderr, "Certificate allocation memory error\n");
		exit(1);
	}

	/* there are some intermediate CAs that have a v1 certificate *%&@#*%&
	 */
	gnutls_certificate_set_verify_flags(xcred,
					    GNUTLS_VERIFY_ALLOW_X509_V1_CA_CRT);

	if (x509_cafile != NULL) {
		ret =
		    gnutls_certificate_set_x509_trust_file(xcred,
							   x509_cafile,
							   x509ctype);
		if (ret < 0) {
			fprintf(stderr,
				"Error setting the x509 trust file\n");
		} else {
			printf("Processed %d CA certificate(s).\n", ret);
		}
	}

	if (x509_certfile != NULL) {
		ret =
		    gnutls_certificate_set_x509_key_file(xcred,
							 x509_certfile,
							 x509_keyfile,
							 x509ctype);
		if (ret < 0) {
			fprintf(stderr,
				"Error setting the x509 key files ('%s', '%s')\n",
				x509_certfile, x509_keyfile);
		}
	}
}
