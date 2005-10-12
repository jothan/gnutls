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
_gnutls_inner_application_recv_params(gnutls_session_t session,
				      const opaque * data,
				      size_t data_size)
{
  unsigned char *p = data;

  if (data_size != 1)
    {
      gnutls_assert ();
      return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
    }

  switch (*p)
    {
    case 0:
      session->security_parameters.extensions.app_phase_on_resumption =
	GNUTLS_APP_PHASE_ON_RESUMPTION_NO;
      break;

    case 1:
      session->security_parameters.extensions.app_phase_on_resumption =
	GNUTLS_APP_PHASE_ON_RESUMPTION_YES;
      break;

    default:
      gnutls_assert();
      return 0;
    }

  return 0;
}

/* returns data_size or a negative number on failure
 */
int
_gnutls_inner_application_send_params(gnutls_session_t session,
				      opaque * data, size_t data_size)
{
  if (!session->security_parameters.extensions.app_phase_on_resumption)
    return 0;

  if (data_size < 1)
    {
      gnutls_assert ();
      return GNUTLS_E_SHORT_MEMORY_BUFFER;
    }

  switch (session->security_parameters.extensions.app_phase_on_resumption)
    {
    case GNUTLS_APP_PHASE_ON_RESUMPTION_NO:
      *data = 0;
      break;

    case GNUTLS_APP_PHASE_ON_RESUMPTION_YES:
      *data = 1;
      break;

    default:
      gnutls_assert();
      return 0;
    }

  return 1;
}

/**
 * gnutls_app_phase_on_resumption_get - Used to get the TLS/IA AppPhaseOnResumption
  * @session: is a #gnutls_session_t structure.
  * @state: will hold the data
  *
  * Extract the TLS/IA client/server hello AppPhaseOnResumption flag.
  **/
void
gnutls_app_phase_on_resumption_get(gnutls_session_t session,
				   gnutls_app_phase_on_resumption_t *state)
{
  *state = session->security_parameters.extensions.app_phase_on_resumption;
}

/**
  * gnutls_app_phase_on_resumption_set - Used to set TLS/IA appPhaseOnResumption
  * @session: is a #gnutls_session_t structure.
  * @yes: appphraseonresumption
  *
  * Set the TLS/IA client/server hello appPhaseOnResumption flag.
  **/
void
gnutls_app_phase_on_resumption_set(gnutls_session_t session,
				   gnutls_app_phase_on_resumption_t state)
{
  session->security_parameters.extensions.app_phase_on_resumption = state;
}
