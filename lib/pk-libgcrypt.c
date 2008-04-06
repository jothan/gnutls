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

/* This file contains code for generation of DSA and RSA keys.
 */

#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <gnutls_datum.h>
#include <x509_int.h>
#include <debug.h>

/* resarr will contain: p(0), q(1), g(2), y(3), x(4).
 */
int
_gnutls_dsa_generate_params (mpi_t * resarr, int *resarr_len, int bits)
{

  int ret;
  gcry_sexp_t parms, key, list;

  /* FIXME: Remove me once we depend on 1.3.1 */
  if (bits > 1024 && gcry_check_version("1.3.1")==NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  if (bits < 512)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  ret = gcry_sexp_build (&parms, NULL, "(genkey(dsa(nbits %d)))", bits);
  if (ret != 0)
    {
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  /* generate the DSA key 
   */
  ret = gcry_pk_genkey (&key, parms);
  gcry_sexp_release (parms);

  if (ret != 0)
    {
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  list = gcry_sexp_find_token (key, "p", 0);
  if (list == NULL)
    {
      gnutls_assert ();
      gcry_sexp_release (key);
      return GNUTLS_E_INTERNAL_ERROR;
    }

  resarr[0] = gcry_sexp_nth_mpi (list, 1, 0);
  gcry_sexp_release (list);

  list = gcry_sexp_find_token (key, "q", 0);
  if (list == NULL)
    {
      gnutls_assert ();
      gcry_sexp_release (key);
      return GNUTLS_E_INTERNAL_ERROR;
    }

  resarr[1] = gcry_sexp_nth_mpi (list, 1, 0);
  gcry_sexp_release (list);

  list = gcry_sexp_find_token (key, "g", 0);
  if (list == NULL)
    {
      gnutls_assert ();
      gcry_sexp_release (key);
      return GNUTLS_E_INTERNAL_ERROR;
    }

  resarr[2] = gcry_sexp_nth_mpi (list, 1, 0);
  gcry_sexp_release (list);

  list = gcry_sexp_find_token (key, "y", 0);
  if (list == NULL)
    {
      gnutls_assert ();
      gcry_sexp_release (key);
      return GNUTLS_E_INTERNAL_ERROR;
    }

  resarr[3] = gcry_sexp_nth_mpi (list, 1, 0);
  gcry_sexp_release (list);


  list = gcry_sexp_find_token (key, "x", 0);
  if (list == NULL)
    {
      gnutls_assert ();
      gcry_sexp_release (key);
      return GNUTLS_E_INTERNAL_ERROR;
    }

  resarr[4] = gcry_sexp_nth_mpi (list, 1, 0);
  gcry_sexp_release (list);


  gcry_sexp_release (key);

  _gnutls_dump_mpi ("p: ", resarr[0]);
  _gnutls_dump_mpi ("q: ", resarr[1]);
  _gnutls_dump_mpi ("g: ", resarr[2]);
  _gnutls_dump_mpi ("y: ", resarr[3]);
  _gnutls_dump_mpi ("x: ", resarr[4]);

  *resarr_len = 5;

  return 0;

}

/* resarr will contain: modulus(0), public exponent(1), private exponent(2),
 * prime1 - p (3), prime2 - q(4), u (5).
 */
int
_gnutls_rsa_generate_params (mpi_t * resarr, int *resarr_len, int bits)
{

  int ret;
  gcry_sexp_t parms, key, list;

  ret = gcry_sexp_build (&parms, NULL, "(genkey(rsa(nbits %d)))", bits);
  if (ret != 0)
    {
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  /* generate the RSA key */
  ret = gcry_pk_genkey (&key, parms);
  gcry_sexp_release (parms);

  if (ret != 0)
    {
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  list = gcry_sexp_find_token (key, "n", 0);
  if (list == NULL)
    {
      gnutls_assert ();
      gcry_sexp_release (key);
      return GNUTLS_E_INTERNAL_ERROR;
    }

  resarr[0] = gcry_sexp_nth_mpi (list, 1, 0);
  gcry_sexp_release (list);

  list = gcry_sexp_find_token (key, "e", 0);
  if (list == NULL)
    {
      gnutls_assert ();
      gcry_sexp_release (key);
      return GNUTLS_E_INTERNAL_ERROR;
    }

  resarr[1] = gcry_sexp_nth_mpi (list, 1, 0);
  gcry_sexp_release (list);

  list = gcry_sexp_find_token (key, "d", 0);
  if (list == NULL)
    {
      gnutls_assert ();
      gcry_sexp_release (key);
      return GNUTLS_E_INTERNAL_ERROR;
    }

  resarr[2] = gcry_sexp_nth_mpi (list, 1, 0);
  gcry_sexp_release (list);

  list = gcry_sexp_find_token (key, "p", 0);
  if (list == NULL)
    {
      gnutls_assert ();
      gcry_sexp_release (key);
      return GNUTLS_E_INTERNAL_ERROR;
    }

  resarr[3] = gcry_sexp_nth_mpi (list, 1, 0);
  gcry_sexp_release (list);


  list = gcry_sexp_find_token (key, "q", 0);
  if (list == NULL)
    {
      gnutls_assert ();
      gcry_sexp_release (key);
      return GNUTLS_E_INTERNAL_ERROR;
    }

  resarr[4] = gcry_sexp_nth_mpi (list, 1, 0);
  gcry_sexp_release (list);


  list = gcry_sexp_find_token (key, "u", 0);
  if (list == NULL)
    {
      gnutls_assert ();
      gcry_sexp_release (key);
      return GNUTLS_E_INTERNAL_ERROR;
    }

  resarr[5] = gcry_sexp_nth_mpi (list, 1, 0);
  gcry_sexp_release (list);

  gcry_sexp_release (key);

  _gnutls_dump_mpi ("n: ", resarr[0]);
  _gnutls_dump_mpi ("e: ", resarr[1]);
  _gnutls_dump_mpi ("d: ", resarr[2]);
  _gnutls_dump_mpi ("p: ", resarr[3]);
  _gnutls_dump_mpi ("q: ", resarr[4]);
  _gnutls_dump_mpi ("u: ", resarr[5]);

  *resarr_len = 6;

  return 0;

}

int
_gnutls_dh_generate_prime (mpi_t * ret_g, mpi_t * ret_n, unsigned int bits)
{
  mpi_t g = NULL, prime = NULL;
  gcry_error_t err;
  int result, times = 0, qbits;
  mpi_t *factors = NULL;

  /* Calculate the size of a prime factor of (prime-1)/2.
   * This is an emulation of the values in "Selecting Cryptographic Key Sizes" paper.
   */
  if (bits < 256)
    qbits = bits / 2;
  else
    {
      qbits = (bits/40) + 105;
    }

  if (qbits & 1)		/* better have an even number */
    qbits++;

  /* find a prime number of size bits.
   */
  do
    {

      if (times)
	{
	  _gnutls_mpi_release (&prime);
	  gcry_prime_release_factors (factors);
	}

      err = gcry_prime_generate (&prime, bits, qbits,
				 &factors, NULL, NULL, GCRY_STRONG_RANDOM,
				 GCRY_PRIME_FLAG_SPECIAL_FACTOR);

      if (err != 0)
	{
	  gnutls_assert ();
	  result = GNUTLS_E_INTERNAL_ERROR;
	  goto cleanup;
	}

      err = gcry_prime_check (prime, 0);

      times++;
    }
  while (err != 0 && times < 10);

  if (err != 0)
    {
      gnutls_assert ();
      result = GNUTLS_E_INTERNAL_ERROR;
      goto cleanup;
    }

  /* generate the group generator.
   */
  err = gcry_prime_group_generator (&g, prime, factors, NULL);
  if (err != 0)
    {
      gnutls_assert ();
      result = GNUTLS_E_INTERNAL_ERROR;
      goto cleanup;
    }

  gcry_prime_release_factors (factors);
  factors = NULL;

  if (ret_g)
    *ret_g = g;
  else
    _gnutls_mpi_release (&g);
  if (ret_n)
    *ret_n = prime;
  else
    _gnutls_mpi_release (&prime);

  return 0;

cleanup:
  gcry_prime_release_factors (factors);
  _gnutls_mpi_release (&g);
  _gnutls_mpi_release (&prime);

  return result;

}


/* Public key operations */

/****************
 * Public key encryption.
 */
int
_gnutls_pk_encrypt (int algo, mpi_t * resarr, mpi_t data,
		    mpi_t * pkey, int pkey_len)
{
  gcry_sexp_t s_ciph, s_data, s_pkey;
  int rc = -1;

  /* make a sexp from pkey */
  switch (algo)
    {
    case GNUTLS_PK_RSA:
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
_gnutls_pk_decrypt (int algo, mpi_t * resarr, mpi_t data, mpi_t * pkey,
		    int pkey_len)
{
  gcry_sexp_t s_plain, s_data, s_pkey;
  int rc = -1;

  /* make a sexp from pkey */
  switch (algo)
    {
    case GNUTLS_PK_RSA:
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
_gnutls_pk_sign (int algo, mpi_t * data, mpi_t hash, mpi_t * pkey,
		 int pkey_len)
{
  gcry_sexp_t s_hash, s_key, s_sig;
  int rc = -1;

  /* make a sexp from pkey */
  switch (algo)
    {
    case GNUTLS_PK_DSA:
      if (pkey_len >= 5)
	rc = gcry_sexp_build (&s_key, NULL,
			      "(private-key(dsa(p%m)(q%m)(g%m)(y%m)(x%m)))",
			      pkey[0], pkey[1], pkey[2], pkey[3], pkey[4]);
      else
	{
	  gnutls_assert ();
	}

      break;
    case GNUTLS_PK_RSA:
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

      if (algo == GNUTLS_PK_DSA)
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
_gnutls_pk_verify (int algo, mpi_t hash, mpi_t * data,
		   mpi_t * pkey, int pkey_len)
{
  gcry_sexp_t s_sig, s_hash, s_pkey;
  int rc = -1;

  /* make a sexp from pkey */
  switch (algo)
    {
    case GNUTLS_PK_DSA:
      if (pkey_len >= 4)
	rc = gcry_sexp_build (&s_pkey, NULL,
			      "(public-key(dsa(p%m)(q%m)(g%m)(y%m)))",
			      pkey[0], pkey[1], pkey[2], pkey[3]);
      break;
    case GNUTLS_PK_RSA:
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
    case GNUTLS_PK_DSA:
      rc = gcry_sexp_build (&s_sig, NULL,
			    "(sig-val(dsa(r%m)(s%m)))", data[0], data[1]);
      break;
    case GNUTLS_PK_RSA:
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
