/*
 * Copyright (C) 2010 Free Software Foundation
 * Author: Ludovic Court�s
 *
 * This file is part of GNUTLS.
 *
 * GNUTLS is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GNUTLS is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNUTLS; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <gnutls/gnutls.h>
#include <gnutls/openpgp.h>

#include "utils.h"
#include <read-file.h>

#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>

static const char message[] = "Hello, brave GNU world!";

/* The OpenPGP key pair for use and the key ID in those keys.  */
static const char pub_key_file[] = "../guile/tests/openpgp-pub.asc";
static const char priv_key_file[] = "../guile/tests/openpgp-sec.asc";
static const char *key_id =
  NULL
  /* FIXME: The values below don't work as expected.  */
  /* "auto" */
  /* "bd572cdcccc07c35" */;

static const char rsa_params_file[] = "../guile/tests/rsa-parameters.pem";

static const int protocols[] = { GNUTLS_TLS1_0, 0 };
static const int cert_types[] = { GNUTLS_CRT_OPENPGP, 0 };
static const int ciphers[] =
  {
    GNUTLS_CIPHER_NULL, GNUTLS_CIPHER_ARCFOUR,
    GNUTLS_CIPHER_AES_128_CBC, GNUTLS_CIPHER_AES_256_CBC,
    0
  };
static const int kx[] =
  {
    GNUTLS_KX_RSA, GNUTLS_KX_RSA_EXPORT,
    GNUTLS_KX_DHE_RSA, GNUTLS_KX_DHE_DSS,
    0
  };
static const int macs[] =
  {
    GNUTLS_MAC_SHA1, GNUTLS_MAC_RMD160, GNUTLS_MAC_MD5,
    0
  };

static void
log_message (int level, const char *message)
{
  fprintf (stderr, "[%5d|%2d] %s", getpid (), level, message);
}


void
doit ()
{
  int err;
  int sockets[2];
  const char *srcdir;
  char *pub_key_path, *priv_key_path;
  pid_t child;

  gnutls_global_init ();

  srcdir = getenv ("srcdir") ?: ".";

  if (debug)
    {
      gnutls_global_set_log_level (10);
      gnutls_global_set_log_function (log_message);
    }

  err = socketpair (PF_UNIX, SOCK_STREAM, 0, sockets);
  if (err != 0)
    fail ("socketpair %s\n", strerror (errno));

  pub_key_path = alloca (strlen (srcdir) + strlen (pub_key_file) + 2);
  strcpy (pub_key_path, srcdir);
  strcat (pub_key_path, "/");
  strcat (pub_key_path, pub_key_file);

  priv_key_path = alloca (strlen (srcdir) + strlen (priv_key_file) + 2);
  strcpy (priv_key_path, srcdir);
  strcat (priv_key_path, "/");
  strcat (priv_key_path, priv_key_file);

  child = fork ();
  if (child == -1)
    fail ("fork %s\n", strerror (errno));

  if (child == 0)
    {
      /* Child process (client).  */
      gnutls_session_t session;
      gnutls_certificate_credentials_t cred;
      ssize_t sent;

      if (debug)
	printf ("client process %i\n", getpid ());

      err = gnutls_init (&session, GNUTLS_CLIENT);
      if (err != 0)
	fail ("client session %d\n", err);

      gnutls_set_default_priority (session);
      gnutls_transport_set_ptr (session,
				(gnutls_transport_ptr_t)(intptr_t) sockets[0]);

      err = gnutls_certificate_allocate_credentials (&cred);
      if (err != 0)
	fail ("client credentials %d\n", err);

      err =
	gnutls_certificate_set_openpgp_key_file2 (cred,
						  pub_key_file, priv_key_file,
						  key_id,
						  GNUTLS_OPENPGP_FMT_BASE64);
      if (err != 0)
	fail ("client openpgp keys %d\n", err);

      err = gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, cred);
      if (err != 0)
	fail ("client credential_set %d\n", err);

      gnutls_protocol_set_priority (session, protocols);
      gnutls_certificate_type_set_priority (session, cert_types);
      gnutls_cipher_set_priority (session, ciphers);
      gnutls_kx_set_priority (session, kx);
      gnutls_mac_set_priority (session, macs);
      gnutls_dh_set_prime_bits (session, 1024);

      err = gnutls_handshake (session);
      if (err != 0)
	fail ("client handshake %d\n", err);
      else if (debug)
	printf ("client handshake successful\n");

      sent = gnutls_record_send (session, message, sizeof (message));
      if (sent != sizeof (message))
	fail ("client sent %li vs. %li\n", sent, sizeof (message));

      err = gnutls_bye (session, GNUTLS_SHUT_RDWR);
      if (err != 0)
	fail ("client bye %d\n", err);

      if (debug)
	printf ("client done\n");
    }
  else
    {
      /* Parent process (server).  */
      gnutls_session_t session;
      gnutls_dh_params_t dh_params;
      gnutls_rsa_params_t rsa_params;
      gnutls_certificate_credentials_t cred;
      char greetings[sizeof (message) * 2];
      ssize_t received;
      pid_t done;
      int status;
      size_t rsa_size;
      gnutls_datum_t rsa_data;

      if (debug)
	printf ("server process %i (child %i)\n", getpid (), child);

      err = gnutls_init (&session, GNUTLS_SERVER);
      if (err != 0)
	fail ("server session %d\n", err);

      gnutls_set_default_priority (session);
      gnutls_transport_set_ptr (session,
				(gnutls_transport_ptr_t)(intptr_t) sockets[1]);

      err = gnutls_certificate_allocate_credentials (&cred);
      if (err != 0)
	fail ("server credentials %d\n", err);

      err =
	gnutls_certificate_set_openpgp_key_file2 (cred,
						  pub_key_file, priv_key_file,
						  key_id,
						  GNUTLS_OPENPGP_FMT_BASE64);
      if (err != 0)
	fail ("server openpgp keys %d\n", err);

      err = gnutls_dh_params_init (&dh_params);
      if (err)
      	fail ("server DH params init %d\n", err);

      err = gnutls_dh_params_generate2 (dh_params, 1024);
      if (err)
      	fail ("server DH params generate %d\n", err);

      gnutls_certificate_set_dh_params (cred, dh_params);

      rsa_data.data =
      	(unsigned char *) read_binary_file (rsa_params_file, &rsa_size);
      rsa_data.size = rsa_size;

      err = gnutls_rsa_params_init (&rsa_params);
      if (err)
	fail ("server RSA params init %d\n", err);

      err = gnutls_rsa_params_import_pkcs1 (rsa_params, &rsa_data,
					    GNUTLS_X509_FMT_PEM);
      if (err)
	fail ("server RSA params import %d\n", err);

      gnutls_certificate_set_rsa_export_params (cred, rsa_params);

      err = gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, cred);
      if (err != 0)
	fail ("server credential_set %d\n", err);

      gnutls_protocol_set_priority (session, protocols);
      gnutls_certificate_type_set_priority (session, cert_types);
      gnutls_cipher_set_priority (session, ciphers);
      gnutls_kx_set_priority (session, kx);
      gnutls_mac_set_priority (session, macs);
      gnutls_certificate_server_set_request (session, GNUTLS_CERT_REQUIRE);

      err = gnutls_handshake (session);
      if (err != 0)
	fail ("server handshake %d\n", err);

      received = gnutls_record_recv (session, greetings, sizeof (greetings));
      if (received != sizeof (message)
	  || memcmp (greetings, message, sizeof (message)))
	fail ("server received %li vs. %li\n", received, sizeof (message));

      err = gnutls_bye (session, GNUTLS_SHUT_RDWR);
      if (err != 0)
	fail ("server bye %d\n", err);

      if (debug)
	printf ("server done\n");

      done = wait (&status);
      if (done < 0)
	fail ("wait %s\n", strerror (errno));

      if (done != child)
	fail ("who's that?! %d\n", done);

      if (WIFEXITED (status))
	{
	  if (WEXITSTATUS (status) != 0)
	    fail ("child exited with status %d\n", WEXITSTATUS (status));
	}
      else if (WIFSIGNALED (status))
	fail ("child stopped by signal %d\n", WTERMSIG (status));
      else
	fail ("child failed: %d\n", status);
    }
}
