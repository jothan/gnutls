#ifndef GNUTLS_PK_GENERIC_H
# define GNUTLS_PK_GENERIC_H

# include <gnutls/crypto.h>

extern gnutls_crypto_pk_st pk_ops;

#define _gnutls_pk_encrypt( algo, ciphertext, plaintext, params) pk_ops.encrypt( algo, ciphertext, plaintext, params)
#define _gnutls_pk_decrypt( algo, ciphertext, plaintext, params) pk_ops.encrypt( algo, ciphertext, plaintext, params)
#define _gnutls_pk_sign( algo, sig, data, params) pk_ops.encrypt( algo, sig, data, params)
#define _gnutls_pk_verify( algo, data, sig, params) pk_ops.encrypt( algo, data, sig, params)

int _gnutls_rsa_generate_params (mpi_t * resarr, int *resarr_len, int bits);
int _gnutls_dsa_generate_params (mpi_t * resarr, int *resarr_len, int bits);

int _gnutls_dh_generate_prime (mpi_t * ret_g, mpi_t * ret_n, unsigned int bits);

#endif
