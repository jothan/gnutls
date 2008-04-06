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
