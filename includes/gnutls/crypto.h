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

#ifndef GNUTLS_CRYPTO_H
# define GNUTLS_CRYPTO_H

typedef struct gnutls_crypto_cipher {
  int (*init)( void** ctx);
  int (*setkey)( void* ctx, const void * key, int keysize);
  int (*setiv)(void* ctx, const void* iv, int ivsize);
  int (*encrypt)(void* ctx, const void* plain, int plainsize, void* encr, int encrsize);
  int (*decrypt)(void* ctx, const void* encr, int encrsize, void* plain, int plainsize);
  void (*deinit)( void* ctx);
} gnutls_crypto_cipher_st;

typedef struct gnutls_crypto_mac {
  int (*init)( void** ctx);
  int (*setkey)( void* ctx, const void * key, int keysize);
  int (*hash)( void* ctx, const void * text, int textsize);
  int (*copy)( void** dst_ctx, void* src_ctx);
  int (*output) ( void* src_ctx, void* digest, int digestsize);
  void (*deinit)( void* ctx);
} gnutls_crypto_mac_st;

typedef enum gnutls_rnd_level
{
  GNUTLS_RND_KEY = 0, /* fatal in many sessions if broken */
  GNUTLS_RND_RANDOM = 1, /* fatal in session if broken */
  GNUTLS_RND_NONCE = 2, /* fatal in parts of session if broken - i.e. vulnerable to statistical analysis */
} gnutls_rnd_level_t;

typedef struct gnutls_crypto_rnd {
  int (*init)( void** ctx);
  int (*rnd) ( void* ctx, int /* gnutls_rnd_level_t */ level, void* data, int datasize);
  void (*deinit)( void* ctx);
} gnutls_crypto_rnd_st;

typedef void* bigint_t;

typedef enum gnutls_bigint_format
{
  GNUTLS_MPI_FORMAT_USG = 0, /* raw unsigned integer format */ 
  GNUTLS_MPI_FORMAT_STD = 1, /* raw signed integer format - always a leading zero when positive */
} gnutls_bigint_format_t;

typedef struct
{
  bigint_t g; /* group generator */
  bigint_t p; /* prime */
} gnutls_group_t;

/* Multi precision integer arithmetic */
typedef struct gnutls_crypto_bigint {
  bigint_t (*bigint_new)( int nbits);
  void (*bigint_release)( bigint_t n);
  int (*bigint_cmp)(const bigint_t m1, const bigint_t m2); /* 0 for equality, > 0 for m1>m2, < 0 for m1<m2 */
  int (*bigint_cmp_ui)(const bigint_t m1, unsigned long m2); /* as bigint_cmp */
  bigint_t (*bigint_mod) (const bigint_t a, const bigint_t b); /* ret = a % b */
  bigint_t (*bigint_set) (bigint_t a, const bigint_t b); /* a = b -> ret == a */
  bigint_t (*bigint_set_ui) (bigint_t a, unsigned long b); /* a = b -> ret == a */
  unsigned int (*bigint_get_nbits)(const bigint_t a);
  bigint_t (*bigint_powm) (bigint_t w, const bigint_t b, const bigint_t e,const bigint_t m); /* w = b ^ e mod m */
  bigint_t (*bigint_addm) (bigint_t w, const bigint_t a, const bigint_t b, const bigint_t m); /* w = a + b mod m */
  bigint_t (*bigint_subm) (bigint_t w, const bigint_t a, const bigint_t b, const bigint_t m); /* w = a - b mod m */
  bigint_t (*bigint_mulm) (bigint_t w, const bigint_t a, const bigint_t b, const bigint_t m); /* w = a * b mod m */
  bigint_t (*bigint_add) (bigint_t w, const bigint_t a, const bigint_t b); /* w = a + b */
  bigint_t (*bigint_sub) (bigint_t w, const bigint_t a, const bigint_t b); /* w = a - b */
  bigint_t (*bigint_mul) (bigint_t w, const bigint_t a, const bigint_t b); /* w = a * b */
  bigint_t (*bigint_add_ui) (bigint_t w, const bigint_t a, unsigned long b); /* w = a + b */
  bigint_t (*bigint_sub_ui) (bigint_t w, const bigint_t a, unsigned long b); /* w = a - b */
  bigint_t (*bigint_mul_ui) (bigint_t w, const bigint_t a, unsigned long b); /* w = a * b */
  bigint_t (*bigint_div) (bigint_t q, const bigint_t a, const bigint_t b); /* q = a / b */
  int (*bigint_prime_check) (const bigint_t pp); /* 0 if prime */
  int (*bigint_generate_group) (gnutls_group_t* gg, unsigned int bits);
  
  bigint_t (*bigint_scan) ( const void* buf, size_t buf_size, gnutls_bigint_format_t format); /* reads an bigint from a buffer */
   /* stores an bigint into the buffer.
    * returns GNUTLS_E_SHORT_MEMORY_BUFFER if buf_size is not sufficient to store this integer,
    * and updates the buf_size;
    */
  int (*bigint_print)( const bigint_t a, void* buf, size_t* buf_size, gnutls_bigint_format_t format); 
  
} gnutls_crypto_bigint_st;

typedef struct pk_params {
  bigint_t * params;
  unsigned int params_nr; /* the number of parameters */
  unsigned int flags;
} pk_params_t;

/* params are:
 * RSA: 
 *  [0] is modulus
 *  [1] is public exponent 
 *  [2] is private exponent (private key only)
 *  [3] is prime1 (p) (private key only)
 *  [4] is prime2 (q) (private key only)
 *  [5] is coefficient (u == inverse of p mod q) (private key only)
 *   
 *  note that other packages use inverse of q mod p,
 *  so we need to perform conversions using fixup_params().
 *
 * DSA: 
 *  [0] is p
 *  [1] is q
 *  [2] is g
 *  [3] is y (public key) 
 *  [4] is x (private key only)
 */

/* Public key algorithms */
typedef struct gnutls_crypto_pk {
  /* The params structure should contain the private or public key
   * parameters, depending on the operation */
  int (*encrypt)( gnutls_pk_algorithm_t, gnutls_datum_t* ciphertext, 
    const gnutls_datum_t* plaintext, const pk_params_t* /* public */);
  int (*decrypt)( gnutls_pk_algorithm_t, gnutls_datum_t* plaintext, 
    const gnutls_datum_t* ciphertext, const pk_params_t* /* private */);

  int (*sign)( gnutls_pk_algorithm_t, gnutls_datum_t* signature, 
    const gnutls_datum_t* data, const pk_params_t* /* private */);
  int (*verify)( gnutls_pk_algorithm_t, const gnutls_datum_t* data, 
    const gnutls_datum_t* signature, const pk_params_t* /* public */);

  int (*generate)( gnutls_pk_algorithm_t, pk_params_t*);
  /* this function should convert params to ones suitable
   * for the above functions
   */
  int (*pk_fixup_private_params)( gnutls_pk_algorithm_t, pk_params_t*);
  
} gnutls_crypto_pk_st;

/* the same... setkey should be null */
typedef gnutls_crypto_mac_st gnutls_crypto_digest_st;

/* priority: infinity for backend algorithms, 90 for kernel algorithms - lowest wins 
 */
int gnutls_crypto_cipher_register( gnutls_cipher_algorithm_t algorithm, int priority, gnutls_crypto_cipher_st* s);
int gnutls_crypto_mac_register( gnutls_mac_algorithm_t algorithm, int priority, gnutls_crypto_mac_st* s);
int gnutls_crypto_digest_register( gnutls_digest_algorithm_t algorithm, int priority, gnutls_crypto_digest_st* s);
int gnutls_crypto_rnd_register( int priority, gnutls_crypto_rnd_st* s);
int gnutls_crypto_bigint_register( int priority, gnutls_crypto_bigint_st* s);
int gnutls_crypto_pk_register( int priority, gnutls_crypto_bigint_st* s);

#endif
