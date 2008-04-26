/*
 * Copyright (C) 2008 Free Software Foundation
 *
 * Author: Nikos Mavrogiannopoulos
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA
 *
 */

int _gnutls_rsa_generate_params (mpi_t * resarr, int *resarr_len, int bits);
int _gnutls_dsa_generate_params (mpi_t * resarr, int *resarr_len, int bits);

int _gnutls_dh_generate_prime (mpi_t * ret_g, mpi_t * ret_n, unsigned int bits);

int _gnutls_pk_encrypt (int algo, mpi_t * resarr, mpi_t data,
    mpi_t * pkey, int pkey_len);
int _gnutls_pk_decrypt (int algo, mpi_t * resarr, mpi_t data, mpi_t * pkey,
    int pkey_len);
int _gnutls_pk_sign (int algo, mpi_t * data, mpi_t hash, mpi_t * pkey,
    int pkey_len);
int _gnutls_pk_verify (int algo, mpi_t hash, mpi_t * data,
    mpi_t * pkey, int pkey_len);
