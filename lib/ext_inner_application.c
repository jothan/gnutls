/*
 * Copyright (C) 2005 Free Software Foundation
 *
 * Author: Simon Josefsson
 *
 * This file is part of GNUTLS.
 *
 * The GNUTLS library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 *
 */

#include "gnutls_int.h"
#include "gnutls_auth_int.h"
#include "gnutls_errors.h"
#include "gnutls_num.h"
#include "ext_inner_application.h"


int
_gnutls_inner_application_recv_params (gnutls_session_t session,
				       const opaque * data, size_t data_size)
{
  tls_ext_st *ext = &session->security_parameters.extensions;
  gnutls_app_phase_on_resumption_t state;

  if (data_size != 1)
    {
      gnutls_assert ();
      return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
    }

  switch ((unsigned char)*data)
    {
    case 0:
      state = GNUTLS_APP_PHASE_ON_RESUMPTION_NO;
      break;

    case 1:
      state = GNUTLS_APP_PHASE_ON_RESUMPTION_YES;
      break;

    default:
      gnutls_assert ();
      return 0;
    }

  if (session->security_parameters.entity == GNUTLS_SERVER)
    ext->client_app_phase_on_resumption = state;
  else
    ext->server_app_phase_on_resumption = state;

  return 0;
}

/* returns data_size or a negative number on failure
 */
int
_gnutls_inner_application_send_params (gnutls_session_t session,
				       opaque * data, size_t data_size)
{
  tls_ext_st *ext = &session->security_parameters.extensions;

  if ((ext->client_app_phase_on_resumption ==
       GNUTLS_APP_PHASE_ON_RESUMPTION_DISABLED) ||
      (ext->client_app_phase_on_resumption ==
       GNUTLS_APP_PHASE_ON_RESUMPTION_DISABLED))
    return 0;

  if (data_size < 1)
    {
      gnutls_assert ();
      return GNUTLS_E_SHORT_MEMORY_BUFFER;
    }

#define NO 0
#define YES 1

  if (session->security_parameters.entity == GNUTLS_CLIENT)
    {
      /* Simple case, just send what the application requested. */

      switch (ext->client_app_phase_on_resumption)
	{
	case GNUTLS_APP_PHASE_ON_RESUMPTION_NO:
	  *data = NO;
	  break;

	case GNUTLS_APP_PHASE_ON_RESUMPTION_YES:
	  *data = YES;
	  break;

	default:
	  gnutls_assert ();
	  return 0;
	}
    }
  else
    {
      /* The server MUST set app_phase_on_resumption to "yes" if the
         client set app_phase_on_resumption to "yes" or if the server
         does not resume the session. */

      if ((ext->client_app_phase_on_resumption ==
	   GNUTLS_APP_PHASE_ON_RESUMPTION_YES ) ||
	  session->internals.resumed == RESUME_FALSE)
	*data = YES;
      /* The server MAY set app_phase_on_resumption to "yes" for a
	 resumed session even if the client set
	 app_phase_on_resumption to "no", as the server may have
	 reason to proceed with one or more application phases. */
      else if (ext->server_app_phase_on_resumption ==
	       GNUTLS_APP_PHASE_ON_RESUMPTION_YES)
	*data = YES;
      else
	*data = NO;
    }

  return 1;
}

/**
 * gnutls_inner_application_client_get - Get Client TLS/IA preference
 * @session: is a #gnutls_session_t structure.
 * @state: will hold the data
 *
 * For a client, this function return the value set by the application
 * itself with gnutls_inner_application_client_set() earlier.  If that
 * function has not been invoked, TLS/IA is disabled, and
 * %GNUTLS_APP_PHASE_ON_RESUMPTION_DISABLED is returned.
 *
 * For a server, after a successful call to gnutls_handshake(), this
 * will contain the client's TLS/IA preference.  A return value of
 * %GNUTLS_APP_PHASE_ON_RESUMPTION_DISABLED then means that the client
 * did not support TLS/IA.  A return value of
 * %GNUTLS_APP_PHASE_ON_RESUMPTION_NO means that the client did not
 * request an Inner Application phase if the session was resumed.  If
 * %GNUTLS_APP_PHASE_ON_RESUMPTION_YES is returned, the client
 * requested an Inner Application phase regardless of whether the
 * session is resumed.
 *
 * Note that the server should not use this return value to decide
 * whether to invoke gnutls_ia_handshake().  This return value only
 * indicate the client's preference.
 **/
gnutls_app_phase_on_resumption_t
gnutls_inner_application_client_get (gnutls_session_t session)
{
  return
    session->security_parameters.extensions.client_app_phase_on_resumption;
}

/**
 * gnutls_inner_application_client_set - Request TLS/IA support from server
 * @session: is a #gnutls_session_t structure.
 * @state: a #gnutls_app_phase_on_resumption_t value to indicate
 *   requested TLS/IA client mode.
 *
 * Set the TLS/IA mode that will be requested by the client in the TLS
 * handshake.  For this function to have any effect, it must be called
 * before gnutls_handshake().  This function does nothing if called in
 * a server.
 *
 * A @state value %GNUTLS_APP_PHASE_ON_RESUMPTION_DISABLED means that
 * the client do not wish to use TLS/IA (the default).
 * %GNUTLS_APP_PHASE_ON_RESUMPTION_NO means that the client request
 * TLS/IA, and that if the TLS session is resumed, that there is no
 * Inner Application phase.  %GNUTLS_APP_PHASE_ON_RESUMPTION_YES means
 * that the client request TLS/IA, and that if the TLS session is
 * resumed, there is an Inner Application phase.
 *
 * Note that the client must check the server mode, using
 * gnutls_inner_application_server_get() after gnutls_handshake() has
 * completed, to decide whether to invoke gnutls_ia_handshake() or
 * not.  That is because the server may request an Inner Application
 * phase even though the client requested that there shouldn't be one.
 **/
void
gnutls_inner_application_client_set (gnutls_session_t session,
				     gnutls_app_phase_on_resumption_t state)
{
  if (session->security_parameters.entity == GNUTLS_CLIENT)
    session->security_parameters.extensions.client_app_phase_on_resumption =
      state;
}

/**
 * gnutls_inner_application_server_get - Get Server TLS/IA preference
 * @session: is a #gnutls_session_t structure.
 *
 * For a server, this function return the value set by the application
 * itself with gnutls_inner_application_server_set() earlier.  If that
 * function has not been invoked, TLS/IA is disabled, and
 * %GNUTLS_APP_PHASE_ON_RESUMPTION_DISABLED is returned.
 *
 * For a client, after a successful call to gnutls_handshake(), this
 * will contain the server's TLS/IA preference.  A return value of
 * %GNUTLS_APP_PHASE_ON_RESUMPTION_DISABLED then means that the server
 * did not support TLS/IA, and the client cannot proceed with the
 * gnutls_ia_handshake().  The client may abort the session at that
 * point.  A return value of %GNUTLS_APP_PHASE_ON_RESUMPTION_NO means
 * that the session is resumed and that no Inner Application phase is
 * necessary.  If %GNUTLS_APP_PHASE_ON_RESUMPTION_YES is returned, the
 * client must invoke the Inner Application phase by calling
 * gnutls_ia_handshake().
 **/
gnutls_app_phase_on_resumption_t
gnutls_inner_application_server_get (gnutls_session_t session)
{
  return
    session->security_parameters.extensions.server_app_phase_on_resumption;
}

/**
 * gnutls_inner_application_server_set - Indicate that server support TLS/IA
 * @session: is a #gnutls_session_t structure.
 * @state: a #gnutls_app_phase_on_resumption_t value to indicate
 *   requested TLS/IA server mode.
 *
 * Call this function to decide which TLS/IA mode the server should
 * operate in.  This function does nothing if called in a client.
 * TLS/IA will only be enabled if the client requests this.
 *
 * A value of %GNUTLS_APP_PHASE_ON_RESUMPTION_DISABLED means that
 * TLS/IA should be disabled regardless of what the client requests
 * (the default).  A value of %GNUTLS_APP_PHASE_ON_RESUMPTION_NO means
 * that the server support TLS/IA, and further that if the session is
 * resumed, and if the client did not request an Inner Application
 * phase (i.e., the client has set the AppPhaseOnResumption flag to
 * no), then the server will not require an Inner Application phase.
 * A value of %GNUTLS_APP_PHASE_ON_RESUMPTION_YES means that if the
 * client requests TLS/IA, the server will always require an Inner
 * Application phase, even if the session is resumed.
 **/
void
gnutls_inner_application_server_set (gnutls_session_t session,
				     gnutls_app_phase_on_resumption_t state)
{
  if (session->security_parameters.entity == GNUTLS_SERVER)
    session->security_parameters.extensions.server_app_phase_on_resumption =
      state;
}

/**
 * gnutls_inner_application_handshake_p:
 * @session: is a #gnutls_session_t structure.
 *
 * Predicate to be used after gnutls_handshake() to decide whether to
 * invoke gnutls_ia_handshake().
 *
 * Return value: non-zero if TLS/IA handshake is expected, zero
 *   otherwise.
 **/
int
gnutls_inner_application_handshake_p (gnutls_session_t session)
{
  tls_ext_st *ext = &session->security_parameters.extensions;
  gnutls_app_phase_on_resumption_t clienttlsia =
    ext->client_app_phase_on_resumption;
  gnutls_app_phase_on_resumption_t servertlsia =
    ext->server_app_phase_on_resumption;

  if (session->security_parameters.entity == GNUTLS_SERVER)
    {
      /* The application doesn't want TLS/IA. */
      if (servertlsia == GNUTLS_APP_PHASE_ON_RESUMPTION_DISABLED)
	return 0;

      /* The client didn't support TLS/IA. */
      if (clienttlsia == GNUTLS_APP_PHASE_ON_RESUMPTION_DISABLED)
	return 0;

      /* The client support TLS/IA, and the server application want an
	 Inner Application phase. */
      if (servertlsia == GNUTLS_APP_PHASE_ON_RESUMPTION_YES)
	return 1;

      /* This is not a resumed session, always require an inner
	 application. */
      if (session->internals.resumed == RESUME_FALSE)
	return 1;

      /* The client support TLS/IA, this is a resumed session, and the
	 server application has permitted the client to decide. */
      return clienttlsia == GNUTLS_APP_PHASE_ON_RESUMPTION_YES;
    }
  else
    {
      /* The server didn't support TLS/IA. */
      if (servertlsia == GNUTLS_APP_PHASE_ON_RESUMPTION_DISABLED)
	return 0;

      /* Don't trick client into starting TLS/IA handshake if it
	 didn't request it.  Buggy server. */
      if (clienttlsia == GNUTLS_APP_PHASE_ON_RESUMPTION_DISABLED)
	return 0;

      /* This is not a resumed session, always require an inner
	 application. */
      if (session->internals.resumed == RESUME_FALSE)
	return 1;

      /* The session is resumed, and we support TLS/IA, so let the
	 server decide. */
      return clienttlsia == GNUTLS_APP_PHASE_ON_RESUMPTION_YES;
    }
}
