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

/* Do PKCS-1 RSA encryption. 
 * params is modulus, public exp.
 */
int
_gnutls_pkcs1_rsa_encrypt (gnutls_datum_t * ciphertext,
			   const gnutls_datum_t * plaintext,
			   mpi_t * params, unsigned params_len,
			   unsigned btype)
{
  unsigned int i, pad;
  int ret;
  mpi_t m, res;
  opaque *edata, *ps;
  size_t k, psize;
  size_t mod_bits;

  mod_bits = _gnutls_mpi_get_nbits (params[0]);
  k = mod_bits / 8;
  if (mod_bits % 8 != 0)
    k++;

  if (plaintext->size > k - 11)
    {
      gnutls_assert ();
      return GNUTLS_E_PK_ENCRYPTION_FAILED;
    }

  edata = gnutls_alloca (k);
  if (edata == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  /* EB = 00||BT||PS||00||D 
   * (use block type 'btype')
   */

  edata[0] = 0;
  edata[1] = btype;
  psize = k - 3 - plaintext->size;

  ps = &edata[2];
  switch (btype)
    {
    case 2:
      /* using public key */
      if (params_len < RSA_PUBLIC_PARAMS)
	{
	  gnutls_assert ();
	  gnutls_afree (edata);
	  return GNUTLS_E_INTERNAL_ERROR;
	}

      ret = _gnutls_rnd (RND_RANDOM, ps, psize);
      if ( ret < 0)
	{
	  gnutls_assert ();
	  gnutls_afree (edata);
	  return ret;
	}
      for (i = 0; i < psize; i++)
	while (ps[i] == 0)
	  {
	    ret = _gnutls_rnd (RND_RANDOM, &ps[i], 1);
	    if (ret < 0)
	      {
		gnutls_assert ();
		gnutls_afree (edata);
		return ret;
	      }
	  }
      break;
    case 1:
      /* using private key */

      if (params_len < RSA_PRIVATE_PARAMS)
	{
	  gnutls_assert ();
	  gnutls_afree (edata);
	  return GNUTLS_E_INTERNAL_ERROR;
	}

      for (i = 0; i < psize; i++)
	ps[i] = 0xff;
      break;
    default:
      gnutls_assert ();
      gnutls_afree (edata);
      return GNUTLS_E_INTERNAL_ERROR;
    }

  ps[psize] = 0;
  memcpy (&ps[psize + 1], plaintext->data, plaintext->size);

  if (_gnutls_mpi_scan_nz (&m, edata, k) != 0)
    {
      gnutls_assert ();
      gnutls_afree (edata);
      return GNUTLS_E_MPI_SCAN_FAILED;
    }
  gnutls_afree (edata);

  if (btype == 2)		/* encrypt */
    ret = _gnutls_pk_encrypt (GNUTLS_PK_RSA, &res, m, params, params_len);
  else				/* sign */
    ret = _gnutls_pk_sign (GNUTLS_PK_RSA, &res, m, params, params_len);

  _gnutls_mpi_release (&m);

  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  _gnutls_mpi_print (res, NULL, &psize);

  if (psize < k)
    {
      /* padding psize */
      pad = k - psize;
      psize = k;
    }
  else if (psize == k)
    {
      pad = 0;
    }
  else
    {				/* psize > k !!! */
      /* This is an impossible situation */
      gnutls_assert ();
      _gnutls_mpi_release (&res);
      return GNUTLS_E_INTERNAL_ERROR;
    }

  ciphertext->data = gnutls_malloc (psize);
  if (ciphertext->data == NULL)
    {
      gnutls_assert ();
      _gnutls_mpi_release (&res);
      return GNUTLS_E_MEMORY_ERROR;
    }
  _gnutls_mpi_print (res, &ciphertext->data[pad], &psize);
  for (i = 0; i < pad; i++)
    ciphertext->data[i] = 0;

  ciphertext->size = k;

  _gnutls_mpi_release (&res);

  return 0;
}


/* Do PKCS-1 RSA decryption. 
 * params is modulus, public exp., private key
 * Can decrypt block type 1 and type 2 packets.
 */
int
_gnutls_pkcs1_rsa_decrypt (gnutls_datum_t * plaintext,
			   const gnutls_datum_t * ciphertext,
			   mpi_t * params, unsigned params_len,
			   unsigned btype)
{
  unsigned k, i;
  int ret;
  mpi_t c, res;
  opaque *edata;
  size_t esize, mod_bits;

  mod_bits = _gnutls_mpi_get_nbits (params[0]);
  k = mod_bits / 8;
  if (mod_bits % 8 != 0)
    k++;

  esize = ciphertext->size;

  if (esize != k)
    {
      gnutls_assert ();
      return GNUTLS_E_PK_DECRYPTION_FAILED;
    }

  if (_gnutls_mpi_scan_nz (&c, ciphertext->data, esize) != 0)
    {
      gnutls_assert ();
      return GNUTLS_E_MPI_SCAN_FAILED;
    }

  /* we can use btype to see if the private key is
   * available.
   */
  if (btype == 2)
    ret = _gnutls_pk_decrypt (GNUTLS_PK_RSA, &res, c, params, params_len);
  else
    {
      ret = _gnutls_pk_encrypt (GNUTLS_PK_RSA, &res, c, params, params_len);
    }
  _gnutls_mpi_release (&c);

  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  _gnutls_mpi_print (res, NULL, &esize);
  edata = gnutls_alloca (esize + 1);
  if (edata == NULL)
    {
      gnutls_assert ();
      _gnutls_mpi_release (&res);
      return GNUTLS_E_MEMORY_ERROR;
    }
  _gnutls_mpi_print (res, &edata[1], &esize);

  _gnutls_mpi_release (&res);

  /* EB = 00||BT||PS||00||D
   * (use block type 'btype')
   *
   * From now on, return GNUTLS_E_DECRYPTION_FAILED on errors, to
   * avoid attacks similar to the one described by Bleichenbacher in:
   * "Chosen Ciphertext Attacks against Protocols Based on RSA
   * Encryption Standard PKCS #1".
   */


  edata[0] = 0;
  esize++;

  if (edata[0] != 0 || edata[1] != btype)
    {
      gnutls_assert ();
      gnutls_afree (edata);
      return GNUTLS_E_DECRYPTION_FAILED;
    }

  ret = GNUTLS_E_DECRYPTION_FAILED;
  switch (btype)
    {
    case 2:
      for (i = 2; i < esize; i++)
	{
	  if (edata[i] == 0)
	    {
	      ret = 0;
	      break;
	    }
	}
      break;
    case 1:
      for (i = 2; i < esize; i++)
	{
	  if (edata[i] == 0 && i > 2)
	    {
	      ret = 0;
	      break;
	    }
	  if (edata[i] != 0xff)
	    {
	      _gnutls_handshake_log ("PKCS #1 padding error");
	      /* PKCS #1 padding error.  Don't use
		 GNUTLS_E_PKCS1_WRONG_PAD here.  */
	      break;
	    }
	}
      break;
    default:
      gnutls_assert ();
      gnutls_afree (edata);
      break;
    }
  i++;

  if (ret < 0)
    {
      gnutls_assert ();
      gnutls_afree (edata);
      return GNUTLS_E_DECRYPTION_FAILED;
    }

  if (_gnutls_sset_datum (plaintext, &edata[i], esize - i) < 0)
    {
      gnutls_assert ();
      gnutls_afree (edata);
      return GNUTLS_E_MEMORY_ERROR;
    }

  gnutls_afree (edata);

  return 0;
}


int
_gnutls_rsa_verify (const gnutls_datum_t * vdata,
		    const gnutls_datum_t * ciphertext, mpi_t * params,
		    int params_len, int btype)
{

  gnutls_datum_t plain;
  int ret;

  /* decrypt signature */
  if ((ret =
       _gnutls_pkcs1_rsa_decrypt (&plain, ciphertext, params, params_len,
				  btype)) < 0)
    {
      gnutls_assert ();
      return ret;
    }

  if (plain.size != vdata->size)
    {
      gnutls_assert ();
      _gnutls_free_datum (&plain);
      return GNUTLS_E_PK_SIG_VERIFY_FAILED;
    }

  if (memcmp (plain.data, vdata->data, plain.size) != 0)
    {
      gnutls_assert ();
      _gnutls_free_datum (&plain);
      return GNUTLS_E_PK_SIG_VERIFY_FAILED;
    }

  _gnutls_free_datum (&plain);

  return 0;			/* ok */
}

/* Do DSA signature calculation. params is p, q, g, y, x in that order.
 */
int
_gnutls_dsa_sign (gnutls_datum_t * signature,
		  const gnutls_datum_t * hash, mpi_t * params,
		  unsigned params_len)
{
  mpi_t rs[2], mdata;
  int ret;
  size_t k;

  k = hash->size;
  if (k < 20)
    {				/* SHA1 or better only */
      gnutls_assert ();
      return GNUTLS_E_PK_SIGN_FAILED;
    }

  if (_gnutls_mpi_scan_nz (&mdata, hash->data, k) != 0)
    {
      gnutls_assert ();
      return GNUTLS_E_MPI_SCAN_FAILED;
    }

  ret = _gnutls_pk_sign (GNUTLS_PK_DSA, rs, mdata, params, params_len);
  /* rs[0], rs[1] now hold r,s */
  _gnutls_mpi_release (&mdata);

  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  ret = _gnutls_encode_ber_rs (signature, rs[0], rs[1]);

  /* free r,s */
  _gnutls_mpi_release (&rs[0]);
  _gnutls_mpi_release (&rs[1]);

  if (ret != 0)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  return 0;
}

/* params is p, q, g, y in that order
 */
int
_gnutls_dsa_verify (const gnutls_datum_t * vdata,
		    const gnutls_datum_t * sig_value, mpi_t * params,
		    int params_len)
{

  mpi_t mdata;
  int ret;
  size_t k;
  mpi_t rs[2];

  if (vdata->size != 20)
    {				/* sha-1 only */
      gnutls_assert ();
      return GNUTLS_E_PK_SIG_VERIFY_FAILED;
    }

  if (_gnutls_decode_ber_rs (sig_value, &rs[0], &rs[1]) != 0)
    {
      gnutls_assert ();
      return GNUTLS_E_MPI_SCAN_FAILED;
    }

  k = vdata->size;
  if (_gnutls_mpi_scan_nz (&mdata, vdata->data, k) != 0)
    {
      gnutls_assert ();
      _gnutls_mpi_release (&rs[0]);
      _gnutls_mpi_release (&rs[1]);
      return GNUTLS_E_MPI_SCAN_FAILED;
    }

  /* decrypt signature */
  ret = _gnutls_pk_verify (GNUTLS_PK_DSA, mdata, rs, params, params_len);
  _gnutls_mpi_release (&mdata);
  _gnutls_mpi_release (&rs[0]);
  _gnutls_mpi_release (&rs[1]);

  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  return 0;			/* ok */
}


/* this is taken from gnupg 
 */

