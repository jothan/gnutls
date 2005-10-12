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

/**
 * gnutls_app_phase_on_resumption_get - Used to get the TLS/IA AppPhaseOnResumption
  * @session: is a #gnutls_session_t structure.
  * @state: will hold the data
  *
  * Extract the TLS/IA client/server hello AppPhaseOnResumption flag.
  **/
void
gnutls_app_phase_on_resumption_get(gnutls_session_t session,
				   gnutls_app_phase_on_resumption_t *state);
{
  *state = session->security_parameters.extensions.appphaseonresumption;
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
				   gnutls_app_phase_on_resumption_t state);
{
  session->security_parameters.extensions.appphaseonresumption = state;
}
