/* Typedefs for more compatibility with older GnuTLS. */

#ifndef _GNUTLS_COMPAT_H
# define _GNUTLS_COMPAT_H

#ifdef __GNUC__

#define _GNUTLS_GCC_VERSION (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)

#if _GNUTLS_GCC_VERSION >= 30100
#define _GNUTLS_GCC_ATTR_DEPRECATED __attribute__ ((__deprecated__))
#endif

#endif /* __GNUC__ */

#ifndef _GNUTLS_GCC_ATTR_DEPRECATED
#define _GNUTLS_GCC_ATTR_DEPRECATED
#endif

#define gnutls_cipher_algorithm gnutls_cipher_algorithm_t
#define gnutls_kx_algorithm gnutls_kx_algorithm_t
#define gnutls_paramsype gnutls_paramsype_t
#define gnutls_mac_algorithm gnutls_mac_algorithm_t
#define gnutls_digest_algorithm gnutls_digest_algorithm_t
#define gnutls_compression_method gnutls_compression_method_t
#define gnutls_connection_end gnutls_connection_end_t
#define gnutls_credentialsype gnutls_credentialsype_t
#define gnutls_certificateype gnutls_certificateype_t
#define gnutls_x509_crt_fmt gnutls_x509_crt_fmt_t
#define gnutls_openpgp_key_fmt gnutls_openpgp_key_fmt_t
#define gnutls_pk_algorithm gnutls_pk_algorithm_t
#define gnutls_sign_algorithm gnutls_sign_algorithm_t
#define gnutls_server_name gnutls_server_nameype_t
#define gnutls_protocol gnutls_protocol_version_t
#define gnutls_close_request gnutls_close_request_t
#define gnutls_openpgp_key_status gnutls_openpgp_key_status_t
#define gnutls_certificate_request gnutls_certificate_request_t
#define gnutls_certificate_status gnutls_certificate_status_t
#define gnutls_session gnutls_session_t
#define gnutls_alert_level gnutls_alert_level_t
#define gnutls_alert_description gnutls_alert_description_t
#define gnutls_x509_subject_alt_name gnutls_x509_subject_alt_name_t
#define gnutls_openpgp_key gnutls_openpgp_key_t
#define gnutls_openpgp_privkey gnutls_openpgp_privkey_t
#define gnutls_openpgp_keyring gnutls_openpgp_keyring_t
#define gnutls_x509_crt gnutls_x509_crt_t
#define gnutls_x509_privkey gnutls_x509_privkey_t
#define gnutls_x509_crl gnutls_x509_crl_t
#define gnutls_pkcs7 gnutls_pkcs7_t
#define gnutls_x509_crq gnutls_x509_crq_t
#define gnutls_pkcs_encrypt_flags gnutls_pkcs_encrypt_flags_t
#define gnutls_pkcs12_bag_type gnutls_pkcs12_bag_type_t
#define gnutls_pkcs12_bag gnutls_pkcs12_bag_t
#define gnutls_pkcs12 gnutls_pkcs12_t
#define gnutls_certificate_credentials gnutls_certificate_credentials_t
#define gnutls_anon_server_credentials gnutls_anon_server_credentials_t
#define gnutls_anon_client_credentials gnutls_anon_client_credentials_t
#define gnutls_srp_client_credentials gnutls_srp_client_credentials_t
#define gnutls_srp_server_credentials gnutls_srp_server_credentials_t
#define gnutls_dh_params gnutls_dh_params_t
#define gnutls_rsa_params gnutls_rsa_params_t
#define gnutls_params_type gnutls_params_type_t
#define gnutls_credentials_type gnutls_credentials_type_t
#define gnutls_certificate_type gnutls_certificate_type_t
#define gnutls_datum gnutls_datum_t
#define gnutls_transport_ptr gnutls_transport_ptr_t

/* Old SRP alerts removed in 2.1.x because the TLS-SRP RFC was
   modified to use the PSK alert. */
#define GNUTLS_A_MISSING_SRP_USERNAME GNUTLS_A_UNKNOWN_PSK_IDENTITY
#define GNUTLS_A_UNKNOWN_SRP_USERNAME GNUTLS_A_UNKNOWN_PSK_IDENTITY

/* OpenPGP stuff renamed in 2.1.x. */
#define gnutls_openpgp_key_fmt_t gnutls_openpgp_crt_fmt_t
#define GNUTLS_OPENPGP_KEY GNUTLS_OPENPGP_CERT
#define GNUTLS_OPENPGP_KEY_FINGERPRINT GNUTLS_OPENPGP_CERT_FINGERPRINT
#define gnutls_openpgp_send_key gnutls_openpgp_send_cert
#define gnutls_openpgp_key_status_t gnutls_openpgp_crt_status_t
#define gnutls_openpgp_key_t gnutls_openpgp_crt_t
#define gnutls_openpgp_key_init gnutls_openpgp_crt_init
#define gnutls_openpgp_key_deinit gnutls_openpgp_crt_deinit
#define gnutls_openpgp_key_import gnutls_openpgp_crt_import
#define gnutls_openpgp_key_export gnutls_openpgp_crt_export
#define gnutls_openpgp_key_get_key_usage gnutls_openpgp_crt_get_key_usage
#define gnutls_openpgp_key_get_fingerprint gnutls_openpgp_crt_get_fingerprint
#define gnutls_openpgp_key_get_pk_algorithm gnutls_openpgp_crt_get_pk_algorithm
#define gnutls_openpgp_key_get_name gnutls_openpgp_crt_get_name
#define gnutls_openpgp_key_get_version gnutls_openpgp_crt_get_version
#define gnutls_openpgp_key_get_creation_time gnutls_openpgp_crt_get_creation_time
#define gnutls_openpgp_key_get_expiration_time gnutls_openpgp_crt_get_expiration_time
#define gnutls_openpgp_key_get_id gnutls_openpgp_crt_get_id
#define gnutls_openpgp_key_check_hostname gnutls_openpgp_crt_check_hostname

/* OpenPGP stuff renamed in 2.3.x. */
#define gnutls_openpgp_crt_get_id gnutls_openpgp_crt_get_key_id

/* New better names renamed in 2.3.x, add these for backwards
   compatibility with old poor names.*/
#define GNUTLS_X509_CRT_FULL GNUTLS_CRT_PRINT_FULL
#define GNUTLS_X509_CRT_ONELINE GNUTLS_CRT_PRINT_ONELINE
#define GNUTLS_X509_CRT_UNSIGNED_FULL GNUTLS_CRT_PRINT_UNSIGNED_FULL

/* These old #define's violate the gnutls_* namespace. */
#define TLS_MASTER_SIZE GNUTLS_MASTER_SIZE
#define TLS_RANDOM_SIZE GNUTLS_RANDOM_SIZE

/* Namespace problems. */
#define LIBGNUTLS_VERSION GNUTLS_VERSION
#define LIBGNUTLS_VERSION_MAJOR GNUTLS_VERSION_MAJOR
#define LIBGNUTLS_VERSION_MINOR GNUTLS_VERSION_MINOR
#define LIBGNUTLS_VERSION_PATCH GNUTLS_VERSION_PATCH
#define LIBGNUTLS_VERSION_NUMBER GNUTLS_VERSION_NUMBER
#define LIBGNUTLS_EXTRA_VERSION GNUTLS_VERSION

  typedef struct gnutls_retr_st
  {
    gnutls_certificate_type_t type;
    union
    {
      gnutls_x509_crt_t *x509;
      gnutls_openpgp_crt_t pgp;
    } cert;
    unsigned int ncerts;	/* one for pgp keys */

    union
    {
      gnutls_x509_privkey_t x509;
      gnutls_openpgp_privkey_t pgp;
    } key;

    unsigned int deinit_all;	/* if non zero all keys will be deinited */
  } gnutls_retr_st;

typedef int gnutls_certificate_client_retrieve_function (gnutls_session_t,
							   const
							   gnutls_datum_t *
							   req_ca_rdn,
							   int nreqs,
							   const
							   gnutls_pk_algorithm_t
							   * pk_algos,
							   int
							   pk_algos_length,
							   gnutls_retr_st *);
typedef int gnutls_certificate_server_retrieve_function (gnutls_session_t,
							   gnutls_retr_st *);

void gnutls_certificate_client_set_retrieve_function
    (gnutls_certificate_credentials_t cred,
     gnutls_certificate_client_retrieve_function * func) _GNUTLS_GCC_ATTR_DEPRECATED;
void gnutls_certificate_server_set_retrieve_function
    (gnutls_certificate_credentials_t cred,
     gnutls_certificate_server_retrieve_function * func) _GNUTLS_GCC_ATTR_DEPRECATED;

  /* External signing callback.  Experimental. */
  typedef int (*gnutls_sign_func) (gnutls_session_t session,
				   void *userdata,
				   gnutls_certificate_type_t cert_type,
				   const gnutls_datum_t * cert,
				   const gnutls_datum_t * hash,
				   gnutls_datum_t * signature);

  void gnutls_sign_callback_set (gnutls_session_t session,
				 gnutls_sign_func sign_func, void *userdata) _GNUTLS_GCC_ATTR_DEPRECATED;
    gnutls_sign_func
    gnutls_sign_callback_get (gnutls_session_t session, void **userdata);

  int gnutls_ext_register (int type,
			   const char *name,
			   gnutls_ext_parse_type_t parse_type,
			   gnutls_ext_recv_func recv_func,
			   gnutls_ext_send_func send_func) _GNUTLS_GCC_ATTR_DEPRECATED;

#endif /* _GNUTLS_COMPAT_H */
