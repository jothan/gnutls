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
 * gnutls_handshake() iff gnutls_inner_application_handshake_p().
 *
 * Return 0 on success, or an error code.
 **/
int
gnutls_ia_handshake (gnutls_session_t session)
{
  return 0;
}
