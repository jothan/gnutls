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
  return 0;
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
  return
    session->security_parameters.extensions.client_app_phase_on_resumption;
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
gnutls_ia_client_set (gnutls_session_t session,
		      gnutls_ia_mode_t state)
{
  if (session->security_parameters.entity == GNUTLS_CLIENT)
    session->security_parameters.extensions.client_app_phase_on_resumption =
      state;
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
  return
    session->security_parameters.extensions.server_app_phase_on_resumption;
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
gnutls_ia_server_set (gnutls_session_t session,
		      gnutls_ia_mode_t state)
{
  if (session->security_parameters.entity == GNUTLS_SERVER)
    session->security_parameters.extensions.server_app_phase_on_resumption =
      state;
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
  gnutls_ia_mode_t clienttlsia = ext->client_app_phase_on_resumption;
  gnutls_ia_mode_t servertlsia = ext->server_app_phase_on_resumption;

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
