/*
 * Copyright (C) 2001, 2002, 2003, 2004, 2005, 2006, 2008 Free Software Foundation
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

/* This file contains the functions needed for RSA/DSA public key
 * encryption and signatures. 
 */

#include <gnutls_int.h>
#include <gnutls_mpi.h>
#include <gnutls_pk.h>
#include <gnutls_errors.h>
#include <gnutls_datum.h>
#include <gnutls_global.h>
#include <gnutls_num.h>
#include "debug.h"
#include <x509/x509_int.h>
#include <x509/common.h>
#include <random.h>
#include <pk-generic.h>

/* this is taken from gnupg 
 */

/****************
 * Emulate our old PK interface here - sometime in the future we might
 * change the internal design to directly fit to libgcrypt.
 */
int
_wrap_gcry_pk_encrypt (int algo, mpi_t * resarr, mpi_t data,
		    mpi_t * pkey, int pkey_len)
{
  gcry_sexp_t s_ciph, s_data, s_pkey;
  int rc = -1;

  /* make a sexp from pkey */
  switch (algo)
    {
    case GCRY_PK_RSA:
      if (pkey_len >= 2)
	rc = gcry_sexp_build (&s_pkey, NULL,
			      "(public-key(rsa(n%m)(e%m)))",
			      pkey[0], pkey[1]);
      break;

    default:
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  if (rc != 0)
    {
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  /* put the data into a simple list */
  if (gcry_sexp_build (&s_data, NULL, "%m", data))
    {
      gnutls_assert ();
      gcry_sexp_release (s_pkey);
      return GNUTLS_E_INTERNAL_ERROR;
    }

  /* pass it to libgcrypt */
  rc = gcry_pk_encrypt (&s_ciph, s_data, s_pkey);
  gcry_sexp_release (s_data);
  gcry_sexp_release (s_pkey);

  if (rc != 0)
    {
      gnutls_assert ();
      return GNUTLS_E_PK_ENCRYPTION_FAILED;

    }
  else
    {				/* add better error handling or make gnupg use S-Exp directly */
      gcry_sexp_t list = gcry_sexp_find_token (s_ciph, "a", 0);
      if (list == NULL)
	{
	  gnutls_assert ();
	  gcry_sexp_release (s_ciph);
	  return GNUTLS_E_INTERNAL_ERROR;
	}

      resarr[0] = gcry_sexp_nth_mpi (list, 1, 0);
      gcry_sexp_release (list);

      if (resarr[0] == NULL)
	{
	  gnutls_assert ();
	  gcry_sexp_release (s_ciph);
	  return GNUTLS_E_INTERNAL_ERROR;
	}
    }

  gcry_sexp_release (s_ciph);
  return rc;
}

int
_wrap_gcry_pk_decrypt (int algo, mpi_t * resarr, mpi_t data, mpi_t * pkey,
		    int pkey_len)
{
  gcry_sexp_t s_plain, s_data, s_pkey;
  int rc = -1;

  /* make a sexp from pkey */
  switch (algo)
    {
    case GCRY_PK_RSA:
      if (pkey_len >= 6)
	rc = gcry_sexp_build (&s_pkey, NULL,
			      "(private-key(rsa((n%m)(e%m)(d%m)(p%m)(q%m)(u%m))))",
			      pkey[0], pkey[1], pkey[2], pkey[3],
			      pkey[4], pkey[5]);
      break;

    default:
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  if (rc != 0)
    {
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  /* put the data into a simple list */
  if (gcry_sexp_build (&s_data, NULL, "(enc-val(rsa(a%m)))", data))
    {
      gnutls_assert ();
      gcry_sexp_release (s_pkey);
      return GNUTLS_E_INTERNAL_ERROR;
    }

  /* pass it to libgcrypt */
  rc = gcry_pk_decrypt (&s_plain, s_data, s_pkey);
  gcry_sexp_release (s_data);
  gcry_sexp_release (s_pkey);

  if (rc != 0)
    {
      gnutls_assert ();
      return GNUTLS_E_PK_DECRYPTION_FAILED;

    }
  else
    {				/* add better error handling or make gnupg use S-Exp directly */
      resarr[0] = gcry_sexp_nth_mpi (s_plain, 0, 0);

      if (resarr[0] == NULL)
	{
	  gnutls_assert ();
	  gcry_sexp_release (s_plain);
	  return GNUTLS_E_INTERNAL_ERROR;
	}
    }

  gcry_sexp_release (s_plain);
  return rc;
}


/* in case of DSA puts into data, r,s
 */
int
_wrap_gcry_pk_sign (int algo, mpi_t * data, mpi_t hash, mpi_t * pkey,
		 int pkey_len)
{
  gcry_sexp_t s_hash, s_key, s_sig;
  int rc = -1;

  /* make a sexp from pkey */
  switch (algo)
    {
    case GCRY_PK_DSA:
      if (pkey_len >= 5)
	rc = gcry_sexp_build (&s_key, NULL,
			      "(private-key(dsa(p%m)(q%m)(g%m)(y%m)(x%m)))",
			      pkey[0], pkey[1], pkey[2], pkey[3], pkey[4]);
      else
	{
	  gnutls_assert ();
	}

      break;
    case GCRY_PK_RSA:
      if (pkey_len >= 6)
	rc = gcry_sexp_build (&s_key, NULL,
			      "(private-key(rsa((n%m)(e%m)(d%m)(p%m)(q%m)(u%m))))",
			      pkey[0], pkey[1], pkey[2], pkey[3],
			      pkey[4], pkey[5]);
      else
	{
	  gnutls_assert ();
	}
      break;

    default:
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  if (rc != 0)
    {
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  /* put the data into a simple list */
  if (gcry_sexp_build (&s_hash, NULL, "%m", hash))
    {
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  /* pass it to libgcrypt */
  rc = gcry_pk_sign (&s_sig, s_hash, s_key);
  gcry_sexp_release (s_hash);
  gcry_sexp_release (s_key);

  if (rc != 0)
    {
      gnutls_assert ();
      return GNUTLS_E_PK_SIGN_FAILED;

    }
  else
    {
      gcry_sexp_t list;

      if (algo == GCRY_PK_DSA)
	{
	  list = gcry_sexp_find_token (s_sig, "r", 0);
	  if (list == NULL)
	    {
	      gnutls_assert ();
	      gcry_sexp_release (s_sig);
	      return GNUTLS_E_INTERNAL_ERROR;
	    }

	  data[0] = gcry_sexp_nth_mpi (list, 1, 0);
	  gcry_sexp_release (list);

	  list = gcry_sexp_find_token (s_sig, "s", 0);
	  if (list == NULL)
	    {
	      gnutls_assert ();
	      gcry_sexp_release (s_sig);
	      return GNUTLS_E_INTERNAL_ERROR;
	    }

	  data[1] = gcry_sexp_nth_mpi (list, 1, 0);
	  gcry_sexp_release (list);
	}
      else
	{			/* GCRY_PK_RSA */
	  list = gcry_sexp_find_token (s_sig, "s", 0);
	  if (list == NULL)
	    {
	      gnutls_assert ();
	      gcry_sexp_release (s_sig);
	      return GNUTLS_E_INTERNAL_ERROR;
	    }

	  data[0] = gcry_sexp_nth_mpi (list, 1, 0);
	  gcry_sexp_release (list);
	}
    }

  gcry_sexp_release (s_sig);
  return 0;
}


int
_wrap_gcry_pk_verify (int algo, mpi_t hash, mpi_t * data,
		   mpi_t * pkey, int pkey_len)
{
  gcry_sexp_t s_sig, s_hash, s_pkey;
  int rc = -1;

  /* make a sexp from pkey */
  switch (algo)
    {
    case GCRY_PK_DSA:
      if (pkey_len >= 4)
	rc = gcry_sexp_build (&s_pkey, NULL,
			      "(public-key(dsa(p%m)(q%m)(g%m)(y%m)))",
			      pkey[0], pkey[1], pkey[2], pkey[3]);
      break;
    case GCRY_PK_RSA:
      if (pkey_len >= 2)
	rc = gcry_sexp_build (&s_pkey, NULL,
			      "(public-key(rsa(n%m)(e%m)))",
			      pkey[0], pkey[1]);
      break;

    default:
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  if (rc != 0)
    {
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  /* put the data into a simple list */
  if (gcry_sexp_build (&s_hash, NULL, "%m", hash))
    {
      gnutls_assert ();
      gcry_sexp_release (s_pkey);
      return GNUTLS_E_INTERNAL_ERROR;
    }

  switch (algo)
    {
    case GCRY_PK_DSA:
      rc = gcry_sexp_build (&s_sig, NULL,
			    "(sig-val(dsa(r%m)(s%m)))", data[0], data[1]);
      break;
    case GCRY_PK_RSA:
      rc = gcry_sexp_build (&s_sig, NULL, "(sig-val(rsa(s%m)))", data[0]);
      break;

    default:
      gnutls_assert ();
      gcry_sexp_release (s_pkey);
      gcry_sexp_release (s_hash);
      return GNUTLS_E_INTERNAL_ERROR;
    }

  if (rc != 0)
    {
      gnutls_assert ();
      gcry_sexp_release (s_pkey);
      gcry_sexp_release (s_hash);
      return GNUTLS_E_INTERNAL_ERROR;
    }

  rc = gcry_pk_verify (s_sig, s_hash, s_pkey);

  gcry_sexp_release (s_sig);
  gcry_sexp_release (s_hash);
  gcry_sexp_release (s_pkey);

  if (rc != 0)
    {
      gnutls_assert ();
      return GNUTLS_E_PK_SIG_VERIFY_FAILED;
    }

  return 0;
}

gnutls_crypto_pk_st pk_ops = {
  .bigint_new = gcry_mpi_new,
  .bigint_cmp = gcry_mpi_cmp,
  .bigint_cmp_ui = gcry_mpi_cmp_ui,  
  .bigint_mod = wrap_gcry_mpi_mod,
  .bigint_set = gcry_mpi_set,
  .bigint_set_ui = gcry_mpi_set_ui,
  .bigint_get_nbits = gcry_mpi_get_nbits,
  .bigint_powm = wrap_gcry_mpi_powm,
  .bigint_addm = wrap_gcry_mpi_addm,
  .bigint_subm = wrap_gcry_mpi_subm,
  .bigint_add = wrap_gcry_mpi_add,
  .bigint_sub = wrap_gcry_mpi_sub,
  .bigint_add_ui = wrap_gcry_mpi_add_ui,
  .bigint_sub_ui = wrap_gcry_mpi_sub_ui,
  .bigint_mul = wrap_gcry_mpi_mul,
  .bigint_mulm = wrap_gcry_mpi_mulm,
  .bigint_mul_ui = wrap_gcry_mpi_mul_ui,
  .bigint_div = wrap_gcry_mpi_div,
  .bigint_prime_check = wrap_gcry_prime_check,
  .bigint_release = gcry_mpi_release,
  .bigint_set_bit = gcry_mpi_set_bit,
  .bigint_clear_bit = gcry_mpi_clear_bit,
  .bigint_print = wrap_gcry_mpi_print,
  .bigint_scan = wrap_gcry_mpi_scan
};
