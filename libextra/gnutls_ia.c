/*
 * Copyright (C) 2005 Free Software Foundation
 *
 * Author: Simon Josefsson
 *
 * This file is part of GNUTLS-EXTRA.
 *
 * GNUTLS-EXTRA is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * GNUTLS-EXTRA is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNUTLS-EXTRA; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 */

#include "gnutls_int.h"
#include "gnutls_record.h"
#include "gnutls_errors.h"
#include "gnutls_num.h"
#include "gnutls_state.h"

struct gnutls_ia_client_credentials_st
{
  gnutls_ia_avp_func avp_func;
  void *avp_ptr;
};

struct gnutls_ia_server_credentials_st
{
  gnutls_ia_avp_func avp_func;
  void *avp_ptr;
};

/*
 * enum {
 *   application_payload(0), intermediate_phase_finished(1),
 *   final_phase_finished(2), (255)
 * } InnerApplicationType;
 *
 * struct {
 *   InnerApplicationType msg_type;
 *   uint24 length;
 *   select (InnerApplicationType) {
 *     case application_payload:           ApplicationPayload;
 *     case intermediate_phase_finished:   IntermediatePhaseFinished;
 *     case final_phase_finished:          FinalPhaseFinished;
 *   } body;
 * } InnerApplication;
 *
 */

static ssize_t
_gnutls_send_inner_application (gnutls_session_t session,
				gnutls_ia_apptype msg_type,
				size_t length, const char *data)
{
  opaque *p;

  p = gnutls_malloc (length + 4);
  if (!p)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  *(unsigned char *) p = (unsigned char) (msg_type & 0xFF);
  _gnutls_write_uint24 (length, p + 1);
  memcpy (p + 4, data, length);

  return _gnutls_send_int (session, GNUTLS_INNER_APPLICATION, -1,
			   p, length + 4);
}

static ssize_t
_gnutls_recv_inner_application (gnutls_session_t session,
				gnutls_ia_apptype * msg_type, char **data)
{
  ssize_t len;
  opaque buf[1024];		/* XXX: loop to increment buffer size? */

  len = _gnutls_recv_int (session, GNUTLS_INNER_APPLICATION, -1, buf, 1024);
  if (len < 4)
    {
      gnutls_assert ();
      return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
    }

  if (_gnutls_read_uint24 (&buf[1]) != len - 4)
    {
      gnutls_assert ();
      return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
    }

  *msg_type = buf[0];
  *data = gnutls_malloc (len - 4);
  if (!*data)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }
  memcpy (*data, buf + 4, len - 4);

  return len - 4;
}

/* XXX rewrite the following two functions as state machines, to
   handle EAGAIN/EINTERRUPTED?  just add more problems to callers,
   though.  */

#define SERVER_FINISHED_LABEL "server phase finished"
#define CLIENT_FINISHED_LABEL "client phase finished"

int
_gnutls_ia_client_handshake (gnutls_session_t session)
{
  char *buf = NULL;
  size_t buflen = 0;
  ssize_t len;
  int ret;
  const gnutls_ia_client_credentials_t cred =
    _gnutls_get_cred (session->key, GNUTLS_CRD_IA, NULL);

  if (cred == NULL)
    return GNUTLS_E_INTERNAL_ERROR;

  while (1)
    {
      gnutls_ia_apptype msg_type;
      char *avp;
      size_t avplen;

      ret = cred->avp_func (session, cred->avp_ptr,
			    buf, buflen, &avp, &avplen);
      if (buf)
	gnutls_free (buf);
      if (ret != GNUTLS_IA_APPLICATION_PAYLOAD)
	{
	  int tmpret;
	  tmpret = gnutls_alert_send (session, GNUTLS_AL_FATAL,
				      GNUTLS_A_INNER_APPLICATION_FAILURE);
	  if (tmpret < 0)
	    gnutls_assert ();
	  return ret;
	}

      len = _gnutls_send_inner_application (session,
					    GNUTLS_IA_APPLICATION_PAYLOAD,
					    avplen, avp);
      gnutls_free (avp);
      if (len < 0)
	return len;
      printf ("client: send len %d\n", len);

      len = _gnutls_recv_inner_application (session, &msg_type, &buf);
      if (len < 0)
	return len;
      buflen = len;
      printf ("client: recv len %d msgtype %d\n", buflen, msg_type);

      if (msg_type == GNUTLS_IA_INTERMEDIATE_PHASE_FINISHED ||
	  msg_type == GNUTLS_IA_FINAL_PHASE_FINISHED)
	{
	  char verify_data[12];

	  ret = _gnutls_PRF (session->security_parameters.inner_secret,
			     TLS_MASTER_SIZE,
			     SERVER_FINISHED_LABEL,
			     strlen (SERVER_FINISHED_LABEL),
			     "", 0, 12, verify_data);
	  if (ret < 0)
	    {
	      int tmpret;
	      tmpret = gnutls_alert_send (session, GNUTLS_AL_FATAL,
					  GNUTLS_A_INNER_APPLICATION_FAILURE);
	      if (tmpret < 0)
		gnutls_assert ();
	      return ret;
	    }

	  if (buflen != 12 || memcmp (verify_data, buf, 12) != 0)
	    {
	      puts ("verify bad");
	      ret = gnutls_alert_send (session, GNUTLS_AL_FATAL,
				       GNUTLS_A_INNER_APPLICATION_VERIFICATION);
	      if (ret < 0)
		{
		  gnutls_assert ();
		  return ret;
		}

	      return 4711;
	    }
	  else
	    puts ("verify ok");

	  ret = _gnutls_PRF (session->security_parameters.inner_secret,
			     TLS_MASTER_SIZE,
			     CLIENT_FINISHED_LABEL,
			     strlen (CLIENT_FINISHED_LABEL),
			     "", 0, 12, verify_data);
	  if (ret < 0)
	    {
	      int tmpret;
	      tmpret = gnutls_alert_send (session, GNUTLS_AL_FATAL,
					  GNUTLS_A_INNER_APPLICATION_FAILURE);
	      if (tmpret < 0)
		gnutls_assert ();
	      return ret;
	    }

	  len = _gnutls_send_inner_application (session, msg_type,
						12, verify_data);
	  if (len < 0)
	    return len;
	  printf ("client: send ack len %d\n", len);

	  if (msg_type == GNUTLS_IA_FINAL_PHASE_FINISHED)
	    break;
	}
    }

  return 0;
}

int
_gnutls_ia_server_handshake (gnutls_session_t session)
{
  gnutls_ia_apptype msg_type;
  ssize_t len;
  char *buf;
  size_t i;
  int ret;
  const gnutls_ia_server_credentials_t cred =
    _gnutls_get_cred (session->key, GNUTLS_CRD_IA, NULL);

  if (cred == NULL)
    return GNUTLS_E_INTERNAL_ERROR;

  do
    {
      char *avp;
      size_t avplen;

      len = _gnutls_recv_inner_application (session, &msg_type, &buf);
      if (len < 0)
	return len;

      printf ("server: recv len %d msgtype %d\n", len, msg_type);
      if (len > 0)
	for (i = 0; i < len; i++)
	  printf ("%02x - %c\n", buf[i] & 0xFF, buf[i]);

      if (msg_type == GNUTLS_IA_INTERMEDIATE_PHASE_FINISHED ||
	  msg_type == GNUTLS_IA_FINAL_PHASE_FINISHED)
	{
	  char verify_data[12];

	  /* XXX check that WE sent inter/final first. */

	  ret = _gnutls_PRF (session->security_parameters.inner_secret,
			     TLS_MASTER_SIZE,
			     CLIENT_FINISHED_LABEL,
			     strlen (CLIENT_FINISHED_LABEL),
			     "", 0, 12, verify_data);
	  if (ret < 0)
	    {
	      int tmpret;
	      tmpret = gnutls_alert_send (session, GNUTLS_AL_FATAL,
					  GNUTLS_A_INNER_APPLICATION_FAILURE);
	      if (tmpret < 0)
		gnutls_assert ();
	      return ret;
	    }

	  if (len != 12 || memcmp (verify_data, buf, 12) != 0)
	    {
	      puts ("server: verify bad");
	      ret = gnutls_alert_send (session, GNUTLS_AL_FATAL,
				       GNUTLS_A_INNER_APPLICATION_VERIFICATION);
	      if (ret < 0)
		{
		  gnutls_assert ();
		  return ret;
		}

	      return 4711;
	    }
	  else
	    puts ("server: verify ok");

	  if (msg_type == GNUTLS_IA_FINAL_PHASE_FINISHED)
	    break;
	  else
	    continue;
	}

      avp = NULL;
      avplen = 0;

      ret = cred->avp_func (session, cred->avp_ptr, buf, len, &avp, &avplen);
      if (ret < 0)
	{
	  int tmpret;
	  tmpret = gnutls_alert_send (session, GNUTLS_AL_FATAL,
				      GNUTLS_A_INNER_APPLICATION_FAILURE);
	  if (tmpret < 0)
	    gnutls_assert ();
	  return ret;
	}

      msg_type = ret;

      if (msg_type == GNUTLS_IA_INTERMEDIATE_PHASE_FINISHED ||
	  msg_type == GNUTLS_IA_FINAL_PHASE_FINISHED)
	{
	  avplen = 12;
	  avp = gnutls_malloc (avplen);
	  if (!avp)
	    {
	      gnutls_assert ();
	      return GNUTLS_E_MEMORY_ERROR;
	    }

	  ret = _gnutls_PRF (session->security_parameters.inner_secret,
			     TLS_MASTER_SIZE,
			     SERVER_FINISHED_LABEL,
			     strlen (SERVER_FINISHED_LABEL),
			     /* XXX specification unclear on seed. */
			     "", 0, avplen, avp);
	  if (ret < 0)
	    {
	      int tmpret;
	      tmpret = gnutls_alert_send (session, GNUTLS_AL_FATAL,
					  GNUTLS_A_INNER_APPLICATION_FAILURE);
	      if (tmpret < 0)
		gnutls_assert ();
	      return ret;
	    }
	}

      len = _gnutls_send_inner_application (session, msg_type, avplen, avp);
      gnutls_free (avp);
      if (len < 0)
	return len;
      printf ("server: send len %d\n", len);
    }
  while (1);

  return 0;
}

/**
 * gnutls_ia_handshake:
 * @session: is a #gnutls_session_t structure.
 *
 * Perform a TLS/IA handshake.  This should be called after
 * gnutls_handshake() iff gnutls_ia_handshake_p().
 *
 * Return 0 on success, or an error code.
 **/
int
gnutls_ia_handshake (gnutls_session_t session)
{
  int ret;

  /* XXX Should we do this when tls ms is set first time? */
  memcpy (session->security_parameters.inner_secret,
	  session->security_parameters.master_secret, TLS_MASTER_SIZE);

  if (session->security_parameters.entity == GNUTLS_CLIENT)
    ret = _gnutls_ia_client_handshake (session);
  else
    ret = _gnutls_ia_server_handshake (session);

  return ret;
}

/**
 * gnutls_ia_allocate_client_credentials - Used to allocate an gnutls_ia_server_credentials_t structure
 * @sc: is a pointer to an #gnutls_ia_server_credentials_t structure.
 *
 * This structure is complex enough to manipulate directly thus this
 * helper function is provided in order to allocate it.
 *
 * Returns 0 on success.
 **/
int
gnutls_ia_allocate_client_credentials (gnutls_ia_client_credentials_t * sc)
{
  *sc = gnutls_calloc (1, sizeof (**sc));

  if (*sc == NULL)
    return GNUTLS_E_MEMORY_ERROR;

  return 0;
}

/**
 * gnutls_ia_free_client_credentials - Used to free an allocated #gnutls_ia_client_credentials_t structure
 * @sc: is an #gnutls_ia_client_credentials_t structure.
 *
 * This structure is complex enough to manipulate directly thus this
 * helper function is provided in order to free (deallocate) it.
 *
 **/
void
gnutls_ia_free_client_credentials (gnutls_ia_client_credentials_t sc)
{
  gnutls_free (sc);
}

/**
 * gnutls_ia_allocate_server_credentials - Used to allocate an gnutls_ia_server_credentials_t structure
 * @sc: is a pointer to an #gnutls_ia_server_credentials_t structure.
 *
 * This structure is complex enough to manipulate directly thus this
 * helper function is provided in order to allocate it.
 *
 * Returns 0 on success.
 **/
int
gnutls_ia_allocate_server_credentials (gnutls_ia_server_credentials_t * sc)
{
  *sc = gnutls_calloc (1, sizeof (**sc));

  if (*sc == NULL)
    return GNUTLS_E_MEMORY_ERROR;

  return 0;
}

/**
 * gnutls_ia_free_server_credentials - Used to free an allocated #gnutls_ia_server_credentials_t structure
 * @sc: is an #gnutls_ia_server_credentials_t structure.
 *
 * This structure is complex enough to manipulate directly thus this
 * helper function is provided in order to free (deallocate) it.
 *
 **/
void
gnutls_ia_free_server_credentials (gnutls_ia_server_credentials_t sc)
{
  gnutls_free (sc);
}

/**
 * gnutls_ia_set_client_avp_function - Used to set a AVP callback
 * @cred: is a #gnutls_ia_client_credentials_t structure.
 * @avp_func: is the callback function
 *
 * Set the TLS/IA AVP callback handler used for the session.
 *
 * The AVP callback is called to process AVPs received from the
 * server, and to get a new AVP to send to the server.
 *
 * The callback's function form is:
 * int (*avp_func) (gnutls_session_t session, void *ptr,
 *                  const char *last, size_t lastlen,
 *                  char **new, size_t *newlen);
 *
 * The @session parameter is the #gnutls_session_t structure
 * corresponding to the current session.  The @ptr parameter is the
 * application hook pointer, set through
 * gnutls_ia_set_client_avp_ptr().  The AVP received from the server
 * is present in @last of @lastlen size, which will be %NULL on the
 * first invocation.  The newly allocated output AVP to send to the
 * server should be placed in *@new of *@newlen size.
 *
 * Return 0 (%GNUTLS_IA_APPLICATION_PAYLOAD) on success, or a negative
 * error code to abort the TLS/IA handshake.
 *
 * Note that the callback must use allocate the @new parameter using
 * gnutls_malloc(), because it is released via gnutls_free() by the
 * TLS/IA handshake function.
 *
 **/
void
gnutls_ia_set_client_avp_function (gnutls_ia_client_credentials_t cred,
				   gnutls_ia_avp_func avp_func)
{
  cred->avp_func = avp_func;
}

/**
 * gnutls_ia_set_client_avp_ptr - Sets a pointer to be sent to TLS/IA callback
 * @cred: is a #gnutls_ia_client_credentials_t structure.
 * @ptr: is the pointer
 *
 * Sets the pointer that will be provided to the TLS/IA callback
 * function as the first argument.
 *
 **/
void
gnutls_ia_set_client_avp_ptr (gnutls_ia_client_credentials_t cred, void *ptr)
{
  cred->avp_ptr = ptr;
}

/**
 * gnutls_ia_get_client_avp_ptr - Returns the pointer which is sent to TLS/IA callback
 * @cred: is a #gnutls_ia_client_credentials_t structure.
 *
 * Returns the pointer that will be provided to the TLS/IA callback
 * function as the first argument.
 *
 **/
void *
gnutls_ia_get_client_avp_ptr (gnutls_ia_client_credentials_t cred)
{
  return cred->avp_ptr;
}

/**
 * gnutls_ia_set_server_credentials_function - Used to set a AVP callback
 * @cred: is a #gnutls_ia_server_credentials_t structure.
 * @func: is the callback function
 *
 * Set the TLS/IA AVP callback handler used for the session.
 *
 * The callback's function form is:
 * int (*avp_func) (gnutls_session_t session, void *ptr,
 *                  const char *last, size_t lastlen,
 *                  char **new, size_t *newlen);
 *
 * The @session parameter is the #gnutls_session_t structure
 * corresponding to the current session.  The @ptr parameter is the
 * application hook pointer, set through
 * gnutls_ia_set_server_avp_ptr().  The AVP received from the client
 * is present in @last of @lastlen size.  The newly allocated output
 * AVP to send to the client should be placed in *@new of *@newlen
 * size.
 *
 * The AVP callback is called to process incoming AVPs from the
 * client, and to get a new AVP to send to the client.  It can also be
 * used to instruct the TLS/IA handshake to do go into the
 * Intermediate or Final phases.  It return a negative error code, or
 * an #gnutls_ia_apptype message type.
 *
 * Specifically, return %GNUTLS_IA_APPLICATION_PAYLOAD (0) to send
 * another AVP to the client, return
 * %GNUTLS_IA_INTERMEDIATE_PHASE_FINISHED (1) to indicate that an
 * IntermediatePhaseFinished message should be sent, and return
 * %GNUTLS_IA_FINAL_PHASE_FINISHED (2) to indicate that an
 * FinalPhaseFinished message should be sent.  In the last two cases,
 * the contents of the @new and @newlen parameter is not used.
 *
 * Note that the callback must use allocate the @new parameter using
 * gnutls_malloc(), because it is released via gnutls_free() by the
 * TLS/IA handshake function.
 **/
void
gnutls_ia_set_server_avp_function (gnutls_ia_server_credentials_t cred,
				   gnutls_ia_avp_func avp_func)
{
  cred->avp_func = avp_func;
}

/**
 * gnutls_ia_set_server_avp_ptr - Sets a pointer to be sent to TLS/IA callback
 * @cred: is a #gnutls_ia_client_credentials_t structure.
 * @ptr: is the pointer
 *
 * Sets the pointer that will be provided to the TLS/IA callback
 * function as the first argument.
 *
 **/
void
gnutls_ia_set_server_avp_ptr (gnutls_ia_server_credentials_t cred, void *ptr)
{
  cred->avp_ptr = ptr;
}

/**
 * gnutls_ia_get_server_avp_ptr - Returns the pointer which is sent to TLS/IA callback
 * @cred: is a #gnutls_ia_client_credentials_t structure.
 *
 * Returns the pointer that will be provided to the TLS/IA callback
 * function as the first argument.
 *
 **/
void *
gnutls_ia_get_server_avp_ptr (gnutls_ia_server_credentials_t cred)
{
  return cred->avp_ptr;
}

/**
 * gnutls_ia_client_get - Get Client TLS/IA preference
 * @session: is a #gnutls_session_t structure.
 *
 * For a client, this function return the value set by the application
 * itself with gnutls_ia_client_set() earlier.  If that function has
 * not been invoked, TLS/IA is disabled, and %GNUTLS_IA_DISABLED is
 * returned.
 *
 * For a server, after a successful call to gnutls_handshake(), this
 * will contain the client's TLS/IA preference.  A return value of
 * %GNUTLS_IA_DISABLED then means that the client did not support
 * TLS/IA.  A return value of %GNUTLS_IA_APP_PHASE_ON_RESUMPTION_NO
 * means that the client did not request an Inner Application phase if
 * the session is resumed.  If %GNUTLS_IA_APP_PHASE_ON_RESUMPTION_YES
 * is returned, the client requested an Inner Application phase
 * regardless of whether the session is resumed or not.
 *
 * Note that the server should not use this function to decide whether
 * to invoke gnutls_ia_handshake(), instead use
 * gnutls_ia_handshake_p().  This return value only indicate the
 * client's preference, which may not be what the server wants to
 * follow.
 *
 * Returns: a #gnutls_ia_mode_t indicating client TLS/IA preference.
 **/
gnutls_ia_mode_t
gnutls_ia_client_get (gnutls_session_t session)
{
  return session->security_parameters.extensions.client_ia_mode;
}

/**
 * gnutls_ia_client_set - Request TLS/IA support from server
 * @session: is a #gnutls_session_t structure.
 * @state: a #gnutls_ia_mode_t value to indicate requested TLS/IA client mode.
 *
 * Set the TLS/IA mode that will be requested by the client in the TLS
 * handshake.  For this function to have any effect, it must be called
 * before gnutls_handshake().  This function does nothing if called in
 * a server.
 *
 * A @state value %GNUTLS_IA_DISABLED means that the client do not
 * wish to use TLS/IA (the default).
 * %GNUTLS_IA_APP_PHASE_ON_RESUMPTION_NO means that the client request
 * TLS/IA, and that if the TLS session is resumed, that there is no
 * Inner Application phase.  %GNUTLS_IA_APP_PHASE_ON_RESUMPTION_YES
 * means that the client request TLS/IA, and that if the TLS session
 * is resumed, there is an Inner Application phase.
 *
 * Note that the client has to check whether the server supported
 * TLS/IA before invoking gnutls_ia_handshake().  Specifically, the
 * client should use gnutls_ia_handshake_p(), after gnutls_handshake()
 * has finished, to decide whether to call gnutls_ia_handshake() or
 * not.
 **/
void
gnutls_ia_client_set (gnutls_session_t session, gnutls_ia_mode_t state)
{
  if (session->security_parameters.entity == GNUTLS_CLIENT)
    session->security_parameters.extensions.client_ia_mode = state;
}

/**
 * gnutls_ia_server_get - Get Server TLS/IA preference
 * @session: is a #gnutls_session_t structure.
 *
 * For a server, this function return the value set by the application
 * itself with gnutls_ia_server_set() earlier.  If that function has
 * not been invoked, TLS/IA is disabled, and %GNUTLS_IA_DISABLED is
 * returned.
 *
 * For a client, after a successful call to gnutls_handshake(), this
 * will contain the server's TLS/IA preference.  A return value of
 * %GNUTLS_IA_DISABLED then means that the server did not support
 * TLS/IA, and the client cannot proceed with the
 * gnutls_ia_handshake().  The client may abort the session at that
 * point, if TLS/IA is required.  A return value of
 * %GNUTLS_IA_APP_PHASE_ON_RESUMPTION_NO means that TLS/IA is
 * supported by the server, and if the session is resumed, there will
 * be no Inner Application phase.  If
 * %GNUTLS_IA_APP_PHASE_ON_RESUMPTION_YES is returned, an Inner
 * Application phase is required.
 *
 * Note that clients is recommended to use gnutls_ia_handshake_p() to
 * decide whether to call gnutls_ia_handshake() or not.
 *
 * Returns: a #gnutls_ia_mode_t indicating server TLS/IA preference.
 **/
gnutls_ia_mode_t
gnutls_ia_server_get (gnutls_session_t session)
{
  return session->security_parameters.extensions.server_ia_mode;
}

/**
 * gnutls_ia_server_set - Indicate that server support TLS/IA
 * @session: is a #gnutls_session_t structure.
 * @state: a #gnutls_ia_mode_t value to indicate requested TLS/IA server mode.
 *
 * Call this function to decide which TLS/IA mode the server should
 * operate in.  This function does nothing if called in a client.
 * TLS/IA will only be enabled if the client requests this.
 *
 * A value of %GNUTLS_IA_DISABLED means that TLS/IA should be disabled
 * regardless of what the client requests (the default).  A value of
 * %GNUTLS_IA_APP_PHASE_ON_RESUMPTION_NO means that the server support
 * TLS/IA, and further that if the session is resumed, and if the
 * client did not request an Inner Application phase (i.e., the client
 * has set the AppPhaseOnResumption flag to no), then the server will
 * not require an Inner Application phase.  A value of
 * %GNUTLS_IA_APP_PHASE_ON_RESUMPTION_YES means that if the client
 * requests TLS/IA, the server will always require an Inner
 * Application phase, even if the session is resumed.
 *
 * Whether to start the TLS/IA handshake depend on whether the client
 * supports or requested TLS/IA.  A server should thus use
 * gnutls_ia_handshake_p() to decide whether to call
 * gnutls_ia_handshake() or not.
 **/
void
gnutls_ia_server_set (gnutls_session_t session, gnutls_ia_mode_t state)
{
  if (session->security_parameters.entity == GNUTLS_SERVER)
    session->security_parameters.extensions.server_ia_mode = state;
}

/**
 * gnutls_ia_handshake_p:
 * @session: is a #gnutls_session_t structure.
 *
 * Predicate to be used after gnutls_handshake() to decide whether to
 * invoke gnutls_ia_handshake().  Usable by both clients and servers.
 *
 * Return value: non-zero if TLS/IA handshake is expected, zero
 *   otherwise.
 **/
int
gnutls_ia_handshake_p (gnutls_session_t session)
{
  tls_ext_st *ext = &session->security_parameters.extensions;
  gnutls_ia_mode_t clienttlsia = ext->client_ia_mode;
  gnutls_ia_mode_t servertlsia = ext->server_ia_mode;

  if (session->security_parameters.entity == GNUTLS_SERVER)
    {
      /* The application doesn't want TLS/IA. */
      if (servertlsia == GNUTLS_IA_DISABLED)
	return 0;

      /* The client didn't support TLS/IA. */
      if (clienttlsia == GNUTLS_IA_DISABLED)
	return 0;

      /* The client support TLS/IA, and the server application want an
         Inner Application phase. */
      if (servertlsia == GNUTLS_IA_APP_PHASE_ON_RESUMPTION_YES)
	return 1;

      /* This is not a resumed session, always require an inner
         application. */
      if (session->internals.resumed == RESUME_FALSE)
	return 1;

      /* The client support TLS/IA, this is a resumed session, and the
         server application has permitted the client to decide. */
      return clienttlsia == GNUTLS_IA_APP_PHASE_ON_RESUMPTION_YES;
    }
  else
    {
      /* The server didn't support TLS/IA. */
      if (servertlsia == GNUTLS_IA_DISABLED)
	return 0;

      /* Don't trick client into starting TLS/IA handshake if it
         didn't request it.  Buggy server. */
      if (clienttlsia == GNUTLS_IA_DISABLED)
	return 0;

      /* This is not a resumed session, always require an inner
         application. */
      if (session->internals.resumed == RESUME_FALSE)
	return 1;

      /* The session is resumed, and we support TLS/IA, so let the
         server decide. */
      return clienttlsia == GNUTLS_IA_APP_PHASE_ON_RESUMPTION_YES;
    }
}
