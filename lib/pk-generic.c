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

#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <pk-generic.h>
#include <gnutls_num.h>

static
int _generate_params(int algo, mpi_t * resarr, int *resarr_len, int bits)
{
gnutls_pk_params_st params;
int ret, i;
	
	ret = pk_ops.generate( GNUTLS_PK_RSA, bits, &params);

	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	if (resarr && resarr_len && *resarr_len > params.params_nr) {
		*resarr_len = params.params_nr;
		for (i=0;i<params.params_nr;i++)
			resarr[i] = params.params[i];
	} else {
		gnutls_assert();
		return GNUTLS_E_INVALID_REQUEST;
	}
	return 0;
}



int _gnutls_rsa_generate_params (mpi_t * resarr, int *resarr_len, int bits)
{
	return _generate_params( GNUTLS_PK_RSA, resarr, resarr_len, bits);
}

int _gnutls_dsa_generate_params (mpi_t * resarr, int *resarr_len, int bits)
{
	return _generate_params( GNUTLS_PK_DSA, resarr, resarr_len, bits);
}

int _gnutls_pk_params_copy( gnutls_pk_params_st* dst, mpi_t* params, int params_len)
{
int i,j;
	dst->params_nr = 0;

	dst->params = gnutls_malloc( sizeof(mpi_t)*params_len);
	if (dst->params == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	for (i=0;i<params_len;i++) {
		dst->params[i] = _gnutls_mpi_set( NULL, params[i]);
		if (dst->params[i] == NULL) {
			for (j=0;j<i;j++)
				_gnutls_mpi_release( &dst->params[j]);
			return GNUTLS_E_MEMORY_ERROR;
		}
		dst->params_nr++;
	}
}

void gnutls_pk_params_init( gnutls_pk_params_st* p)
{
	memset( p, 0, sizeof(gnutls_pk_params_st));
}

void gnutls_pk_params_release( gnutls_pk_params_st* p)
{
int i;
	for (i=0;i<p->params_nr;i++) {
		_gnutls_mpi_release( &p->params[i]);
	}
	gnutls_free( p->params);
	p->params = NULL;
}
