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

#define CHECKSUM_SIZE 12

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

static const char server_finished_label[] = "server phase finished";
static const char client_finished_label[] = "client phase finished";
static const char inner_permutation_label[] = "inner secret permutation";
static const char challenge_label[] = "inner application challenge";

/*
 * The TLS/IA packet is the InnerApplication token, described as
 * follows in draft-funk-tls-inner-application-extension-01.txt:
 *
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

/* Send TLS/IA data.  If data==NULL && sizeofdata==NULL, then the last
   send was interrupted for some reason, and then we try to send it
   again.  Returns the number of bytes sent, or an error code.  If
   this return E_AGAIN and E_INTERRUPTED, call this function again
   with data==NULL&&sizeofdata=0NULL until it returns successfully. */
static ssize_t
_gnutls_send_inner_application (gnutls_session_t session,
				gnutls_ia_apptype_t msg_type,
				const char *data, size_t sizeofdata)
{
  opaque *p = NULL;
  size_t plen = 0;
  ssize_t len;

  if (data != NULL)
    {
      plen = sizeofdata + 4;
      p = gnutls_malloc (plen);
      if (!p)
	{
	  gnutls_assert ();
	  return GNUTLS_E_MEMORY_ERROR;
	}

      *(unsigned char *) p = (unsigned char) (msg_type & 0xFF);
      _gnutls_write_uint24 (sizeofdata, p + 1);
      memcpy (p + 4, data, sizeofdata);
    }

  len = _gnutls_send_int (session, GNUTLS_INNER_APPLICATION, -1, p, plen);

  if (p)
    gnutls_free (p);

  return len;
}

/* Receive TLS/IA data.  Store received TLS/IA message type in
   *MSG_TYPE, and the data in DATA of max SIZEOFDATA size.  Return the
   number of bytes read, or an error code. */
static ssize_t
_gnutls_recv_inner_application (gnutls_session_t session,
				gnutls_ia_apptype_t * msg_type,
				opaque *data, size_t sizeofdata)
{
  ssize_t len;
  opaque pkt[4];

  len = _gnutls_recv_int (session, GNUTLS_INNER_APPLICATION, -1, pkt, 4);
  if (len != 4)
    {
      gnutls_assert ();
      return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
    }

  *msg_type = pkt[0];
  len = _gnutls_read_uint24 (&pkt[1]);

  if (*msg_type != GNUTLS_IA_APPLICATION_PAYLOAD && len != CHECKSUM_SIZE)
    {
      gnutls_assert ();
      return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
    }

  if (sizeofdata < len)
    {
      /* XXX push back pkt to IA buffer? */
      gnutls_assert ();
      return GNUTLS_E_SHORT_MEMORY_BUFFER;
    }

  if (len > 0)
    {
      int tmplen = len;

      len = _gnutls_recv_int (session, GNUTLS_INNER_APPLICATION, -1,
			      data, tmplen);
      if (len != tmplen)
	{
	  gnutls_assert ();
	  /* XXX Correct? */
	  return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
	}
    }

  return len;
}

/* Apply the TLS PRF using the TLS/IA inner secret as keying material,
   where the seed is the client random concatenated with the server
   random concatenated EXTRA of EXTRA_SIZE length (which can be NULL/0
   respectively).  LABEL and LABEL_SIZE is used as the label.  The
   result is placed in pre-allocated OUT of OUTSIZE length. */
static int
_gnutls_ia_prf (gnutls_session_t session,
		size_t label_size,
		const char *label,
		size_t extra_size,
		const char *extra,
		size_t outsize,
		opaque *out)
{
  int ret;
  opaque *seed;
  size_t seedsize = 2 * TLS_RANDOM_SIZE + extra_size;

  seed = gnutls_malloc (seedsize);
  if (!seed)
    {
      gnutls_assert();
      return GNUTLS_E_MEMORY_ERROR;
    }

  memcpy (seed, session->security_parameters.server_random, TLS_RANDOM_SIZE);
  memcpy (seed + TLS_RANDOM_SIZE, session->security_parameters.client_random,
	  TLS_RANDOM_SIZE);
  memcpy (seed + 2 * TLS_RANDOM_SIZE, extra, extra_size);

  ret = _gnutls_PRF (session->security_parameters.inner_secret,
		     TLS_MASTER_SIZE,
		     label,
		     label_size,
		     seed,
		     seedsize,
		     outsize,
		     out);

  gnutls_free (seed);

  return ret;
}

/**
 * gnutls_ia_permute_inner_secret:
 * @session: is a #gnutls_session_t structure.
 * @session_keys_size: Size of generated session keys (0 if none).
 * @session_keys: Generated session keys, used to permute inner secret
 *                (NULL if none).
 *
 * Permute the inner secret using the generated session keys.
 *
 * This can be called in the TLS/IA AVP callback to mix any generated
 * session keys with the TLS/IA inner secret.
 *
 * Return value: Return zero on success, or a negative error code.
 **/
int
gnutls_ia_permute_inner_secret (gnutls_session_t session,
				size_t session_keys_size,
				const char *session_keys)
{
  return _gnutls_ia_prf (session,
			 sizeof (inner_permutation_label) - 1,
			 inner_permutation_label,
			 session_keys_size,
			 session_keys,
			 TLS_RANDOM_SIZE,
			 session->security_parameters.inner_secret);
}

/**
 * gnutls_ia_generate_challenge:
 * @session: is a #gnutls_session_t structure.
 * @buffer_size: size of output buffer.
 * @buffer: pre-allocated buffer to contain @buffer_size bytes of output.
 *
 * Generate an application challenge that the client cannot control or
 * predict, based on the TLS/IA inner secret.
 *
 * Return value: Returns 0 on success, or an negative error code.
 **/
int
gnutls_ia_generate_challenge (gnutls_session_t session,
			      size_t buffer_size,
			      char *buffer)
{
  return _gnutls_ia_prf (session,
			 sizeof (challenge_label) - 1,
			 challenge_label,
			 0,
			 NULL,
			 buffer_size,
			 buffer);
}

/**
 * gnutls_ia_extract_inner_secret:
 * @session: is a #gnutls_session_t structure.
 * @buffer: pre-allocated buffer to hold 48 bytes of inner secret.
 *
 * Copy the 48 bytes large inner secret into the specified buffer
 *
 * This function is typically used after the TLS/IA handshake has
 * concluded.  The TLS/IA inner secret can be used as input to a PRF
 * to derive session keys.  Do not use the inner secret directly as a
 * session key, because for a resumed session that does not include an
 * application phase, the inner secret will be identical to the inner
 * secret in the original session.  It is important to include, for
 * example, the client and server randomness when deriving a sesssion
 * key from the inner secret.
 **/
void
gnutls_ia_extract_inner_secret (gnutls_session_t session,
				char *buffer)
{
  memcpy (buffer, session->security_parameters.inner_secret, TLS_MASTER_SIZE);
}

/**
 * gnutls_ia_endphase_send:
 * @session: is a #gnutls_session_t structure.
 * @final_p: Set iff this should signal the final phase.
 *
 * Send a TLS/IA end phase message.
 *
 * In the client, this should only be used to acknowledge an end phase
 * message sent by the server.
 *
 * In the server, this can be called instead of gnutls_ia_send() if
 * the server wishes to end an application phase.
 *
 * Return value: Return 0 on success, or an error code.
 **/
int
gnutls_ia_endphase_send(gnutls_session_t session, int final_p)
{
  opaque local_checksum[CHECKSUM_SIZE];
  int client = session->security_parameters.entity == GNUTLS_CLIENT;
  const char *label = client ? client_finished_label : server_finished_label;
  int size_of_label = client ? sizeof (client_finished_label) :
    sizeof (server_finished_label);
  ssize_t len;
  int ret;

  ret = _gnutls_PRF (session->security_parameters.inner_secret,
		     TLS_MASTER_SIZE,
		     label, size_of_label - 1,
		     /* XXX specification unclear on seed. */
		     "", 0, CHECKSUM_SIZE, local_checksum);
  if (ret < 0)
    return ret;

  len = _gnutls_send_inner_application
    (session,
     final_p ? GNUTLS_IA_FINAL_PHASE_FINISHED :
     GNUTLS_IA_INTERMEDIATE_PHASE_FINISHED,
     local_checksum, CHECKSUM_SIZE);

  /* XXX  Instead of calling this function over and over...?
   * while (len == GNUTLS_E_AGAIN || len == GNUTLS_E_INTERRUPTED)
   *  len = _gnutls_io_write_flush(session);
   */

  if (len < 0)
    {
      gnutls_assert();
      return len;
    }

  return 0;
}

/* Verify TLS/IA end phase CHECKSUM.  It will send an
   GNUTLS_A_INNER_APPLICATION_VERIFICATION alert to the server if
   verification fails.  Return 0 on success, or an error. */
static int
_gnutls_ia_verify_endphase (gnutls_session_t session, char *checksum)
{
  char local_checksum[CHECKSUM_SIZE];
  int client = session->security_parameters.entity == GNUTLS_CLIENT;
  const char *label = client ? server_finished_label : client_finished_label;
  int size_of_label = client ? sizeof (server_finished_label) :
    sizeof (client_finished_label);
  int ret;

  ret = _gnutls_PRF (session->security_parameters.inner_secret,
		     TLS_MASTER_SIZE,
		     label, size_of_label - 1,
		     "", 0, CHECKSUM_SIZE, local_checksum);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  if (memcmp (local_checksum, checksum, CHECKSUM_SIZE) != 0)
    {
      ret = gnutls_alert_send (session, GNUTLS_AL_FATAL,
			       GNUTLS_A_INNER_APPLICATION_VERIFICATION);
      if (ret < 0)
	{
	  gnutls_assert ();
	  return ret;
	}

      return GNUTLS_E_IA_VERIFY_FAILED;
    }

  return 0;
}

/**
 * gnutls_ia_send: Send peer the specified TLS/IA data.
 * @session: is a #gnutls_session_t structure.
 * @data: contains the data to send
 * @sizeofdata: is the length of the data
 *
 * Send TLS/IA application payload data.  This function has the
 * similar semantics with send(). The only difference is that is
 * accepts a GNUTLS session, and uses different error codes.
 *
 * The TLS/IA protocol is synchronous, so you cannot send more than
 * one packet at a time.  The client always send the first packet.
 *
 * To finish an application phase in the server, use
 * gnutls_ia_endphase_send().  The client cannot end an application
 * phase.
 *
 * If the EINTR is returned by the internal push function (the default
 * is send()} then %GNUTLS_E_INTERRUPTED will be returned.  If
 * %GNUTLS_E_INTERRUPTED or %GNUTLS_E_AGAIN is returned, you must call
 * this function again, with the same parameters; alternatively you
 * could provide a %NULL pointer for data, and 0 for size.
 *
 * Returns the number of bytes sent, or a negative error code.
 **/
ssize_t
gnutls_ia_send (gnutls_session_t session, char *data, size_t sizeofdata)
{
  ssize_t len;

  len = _gnutls_send_inner_application (session,
					GNUTLS_IA_APPLICATION_PAYLOAD,
					data, sizeofdata);

  return len;
}

/**
 * gnutls_ia_recv - read data from the TLS/IA protocol
 * @session: is a #gnutls_session_t structure.
 * @data: the buffer that the data will be read into, must hold >= 12 bytes.
 * @sizeofdata: the number of requested bytes, must be >= 12.
 *
 * Receive TLS/IA data.  This function has the similar semantics with
 * recv(). The only difference is that is accepts a GNUTLS session,
 * and uses different error codes.
 *
 * If the received message is an end phase message, the checksum will
 * be verified.
 *
 * If EINTR is returned by the internal push function (the default is
 * @code{recv()}) then GNUTLS_E_INTERRUPTED will be returned.  If
 * GNUTLS_E_INTERRUPTED or GNUTLS_E_AGAIN is returned, you must call
 * this function again, with the same parameters; alternatively you
 * could provide a NULL pointer for data, and 0 for size.
 *
 * Returns the number of bytes received.  A negative error code is
 * returned in case of an error.  The
 * %GNUTLS_E_WARNING_IA_IPHF_RECEIVED is returned when a intermediate
 * phase finished message has been successfully received, and
 * %GNUTLS_E_WARNING_IA_FPHF_RECEIVED when a final phase finished
 * message has been successfully received.  If the checksum
 * verification of the end phase message, %GNUTLS_E_IA_VERIFY_FAILED
 * is returned.
 **/
ssize_t
gnutls_ia_recv (gnutls_session_t session, char *data, size_t sizeofdata)
{
  gnutls_ia_apptype_t msg_type;
  ssize_t len;

  len = _gnutls_recv_inner_application (session, &msg_type,
					data, sizeofdata);

  if (msg_type != GNUTLS_IA_APPLICATION_PAYLOAD)
    {
      int ret;

      ret = _gnutls_ia_verify_endphase (session, data);
      if (ret < 0)
	return ret;

      if (session->security_parameters.entity == GNUTLS_CLIENT)
	{
	  ret = gnutls_ia_endphase_send
	    (session, msg_type == GNUTLS_IA_FINAL_PHASE_FINISHED);
	  if (ret < 0)
	    return ret;
	}

      if (msg_type == GNUTLS_IA_INTERMEDIATE_PHASE_FINISHED)
	return GNUTLS_E_WARNING_IA_IPHF_RECEIVED;
      else if (msg_type == GNUTLS_IA_FINAL_PHASE_FINISHED)
	return GNUTLS_E_WARNING_IA_FPHF_RECEIVED;
    }

  return len;
}

/* XXX rewrite the following two functions as state machines, to
   handle EAGAIN/EINTERRUPTED?  just add more problems to callers,
   though.  */

int
_gnutls_ia_client_handshake (gnutls_session_t session)
{
  char *buf = NULL;
  size_t buflen = 0;
  char tmp[1024];		/* XXX */
  ssize_t len;
  int ret;
  const struct gnutls_ia_client_credentials_st * cred =
    _gnutls_get_cred (session->key, GNUTLS_CRD_IA, NULL);

  if (cred == NULL)
    return GNUTLS_E_INTERNAL_ERROR;

  while (1)
    {
      char *avp;
      size_t avplen;

      ret = cred->avp_func (session, cred->avp_ptr,
			    buf, buflen, &avp, &avplen);
      if (ret)
	{
	  int tmpret;
	  tmpret = gnutls_alert_send (session, GNUTLS_AL_FATAL,
				      GNUTLS_A_INNER_APPLICATION_FAILURE);
	  if (tmpret < 0)
	    gnutls_assert ();
	  return ret;
	}

      len = gnutls_ia_send (session, avp, avplen);
      gnutls_free (avp);
      if (len < 0)
	return len;

      len = gnutls_ia_recv (session, tmp, sizeof (tmp));
      if (len == GNUTLS_E_WARNING_IA_IPHF_RECEIVED)
	{
	  buf = NULL;
	  buflen = 0;
	  continue;
	}
      else if (len == GNUTLS_E_WARNING_IA_FPHF_RECEIVED)
	break;

      if (len < 0)
	return len;

      buflen = len;
      buf = tmp;
    }

  return 0;
}

int
_gnutls_ia_server_handshake (gnutls_session_t session)
{
  gnutls_ia_apptype_t msg_type;
  ssize_t len;
  char buf[1024];
  int ret;
  const struct gnutls_ia_server_credentials_st * cred =
    _gnutls_get_cred (session->key, GNUTLS_CRD_IA, NULL);

  if (cred == NULL)
    return GNUTLS_E_INTERNAL_ERROR;

  do
    {
      char *avp;
      size_t avplen;

      len = gnutls_ia_recv (session, buf, sizeof (buf));
      if (len == GNUTLS_E_WARNING_IA_IPHF_RECEIVED)
	continue;
      else if (len == GNUTLS_E_WARNING_IA_FPHF_RECEIVED)
	break;

      if (len < 0)
	return len;

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

      if (msg_type != GNUTLS_IA_APPLICATION_PAYLOAD)
	{
	  ret = gnutls_ia_endphase_send (session, msg_type ==
					 GNUTLS_IA_FINAL_PHASE_FINISHED);
	  if (ret < 0)
	    return ret;
	}
      else
	{
	  len = gnutls_ia_send (session, avp, avplen);
	  gnutls_free (avp);
	  if (len < 0)
	    return len;
	}
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
 * The callback may invoke gnutls_ia_permute_inner_secret() to mix any
 * generated session keys with the TLS/IA inner secret.
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
 * an #gnutls_ia_apptype_t message type.
 *
 * The callback may invoke gnutls_ia_permute_inner_secret() to mix any
 * generated session keys with the TLS/IA inner secret.
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
