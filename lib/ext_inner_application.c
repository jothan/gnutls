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

#define NO 0
#define YES 1

int
_gnutls_inner_application_recv_params (gnutls_session_t session,
				       const opaque * data, size_t data_size)
{
  tls_ext_st *ext = &session->security_parameters.extensions;
  gnutls_ia_mode_t state;

  if (data_size != 1)
    {
      gnutls_assert ();
      return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
    }

  switch ((unsigned char)*data)
    {
    case NO:
      state = GNUTLS_IA_APP_PHASE_ON_RESUMPTION_NO;
      break;

    case YES:
      state = GNUTLS_IA_APP_PHASE_ON_RESUMPTION_YES;
      break;

    default:
      gnutls_assert ();
      return 0;
    }

  if (session->security_parameters.entity == GNUTLS_SERVER)
    ext->client_ia_mode = state;
  else
    ext->server_ia_mode = state;

  return 0;
}

/* returns data_size or a negative number on failure
 */
int
_gnutls_inner_application_send_params (gnutls_session_t session,
				       opaque * data, size_t data_size)
{
  tls_ext_st *ext = &session->security_parameters.extensions;

  if ((ext->client_ia_mode == GNUTLS_IA_DISABLED) ||
      (ext->client_ia_mode == GNUTLS_IA_DISABLED))
    return 0;

  if (data_size < 1)
    {
      gnutls_assert ();
      return GNUTLS_E_SHORT_MEMORY_BUFFER;
    }

  if (session->security_parameters.entity == GNUTLS_CLIENT)
    {
      /* Simple case, just send what the application requested. */

      switch (ext->client_ia_mode)
	{
	case GNUTLS_IA_APP_PHASE_ON_RESUMPTION_NO:
	  *data = NO;
	  break;

	case GNUTLS_IA_APP_PHASE_ON_RESUMPTION_YES:
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

      if ((ext->client_ia_mode == GNUTLS_IA_APP_PHASE_ON_RESUMPTION_YES ) ||
	  session->internals.resumed == RESUME_FALSE)
	*data = YES;
      /* The server MAY set app_phase_on_resumption to "yes" for a
	 resumed session even if the client set
	 app_phase_on_resumption to "no", as the server may have
	 reason to proceed with one or more application phases. */
      else if (ext->server_ia_mode == GNUTLS_IA_APP_PHASE_ON_RESUMPTION_YES)
	*data = YES;
      else
	*data = NO;
    }

  return 1;
}
