#ifndef GNUTLS_PK_GENERIC_H
# define GNUTLS_PK_GENERIC_H

# include <gnutls/crypto.h>

extern gnutls_crypto_pk_st pk_ops;

#define _gnutls_pk_encrypt( algo, ciphertext, plaintext, params) pk_ops.encrypt( algo, ciphertext, plaintext, params)
#define _gnutls_pk_decrypt( algo, ciphertext, plaintext, params) pk_ops.encrypt( algo, ciphertext, plaintext, params)
#define _gnutls_pk_sign( algo, sig, data, params) pk_ops.encrypt( algo, sig, data, params)
#define _gnutls_pk_verify( algo, data, sig, params) pk_ops.encrypt( algo, data, sig, params)

inline static int
_gnutls_pk_fixup( gnutls_pk_algorithm_t algo, gnutls_direction_t direction, gnutls_pk_params_st* params)
{
	if (pk_ops.pk_fixup_private_params) return pk_ops.pk_fixup_private_params(algo, direction, params);
	return 0;
}

int _gnutls_pk_params_copy( gnutls_pk_params_st* dst, mpi_t* params, int params_len);
void _gnutls_pk_params_release( gnutls_pk_params_st* p);

int _gnutls_rsa_generate_params (mpi_t * resarr, int *resarr_len, int bits);
int _gnutls_dsa_generate_params (mpi_t * resarr, int *resarr_len, int bits);

#endif
