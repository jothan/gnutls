#ifndef __GNUTLS_PKCS11_H
#define __GNUTLS_PKCS11_H

/**
 * @addtogroup gnutls_pkcs11 GnuTLS PKCS#11 interface.
 *
 * @{
 */

/**
 * @file gnutls-pkcs11.h
 * @brief gnutls-pkcs11 interface.
 * @author Alon Bar-Lev <alon.barlev@gmail.com>
 * @see @ref gnutls_pkcs11
 */

#include <stdarg.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>


#define GNUTLS_PKCS11_MAX_PIN_LEN 32

/**
 * @brief Token prompt callback.
 * @param global_data	Callback data.
 * @param label		Token label.
 * @param retry		Retry counter.
 * @return none zero on success.
 */
typedef int (*gnutls_pkcs11_token_callback_t)(
	void * const global_data,
	const char * const label,
	const unsigned retry
);

/* flags */
#define GNUTLS_PKCS11_PIN_FINAL_TRY 1
#define GNUTLS_PKCS11_PIN_COUNT_LOW 2

/* Callback for PKCS#11 PIN entry.  The callback provides the PIN code
 * to unlock the token with label 'token_label' in the slot described
 * by 'slot_descr'.
 *
 * The PIN code, as a NUL-terminated ASCII string, should be copied
 * into the 'pin' buffer (of fixed length NE_SSL_P11PINLEN), and
 * return 0 to indicate success. Alternatively, the callback may
 * return -1 to indicate failure and cancel PIN entry (in which case,
 * the contents of the 'pin' parameter are ignored).
 *
 * When a PIN is required, the callback will be invoked repeatedly
 * (and indefinitely) until either the returned PIN code is correct,
 * the callback returns failure, or the token refuses login (e.g. when
 * the token is locked due to too many incorrect PINs!).  For the
 * first such invocation, the 'attempt' counter will have value zero;
 * it will increase by one for each subsequent attempt.
 *
 * The NE_SSL_P11PIN_COUNT_LOW and/or NE_SSL_P11PIN_FINAL_TRY hints
 * may be set in the 'flags' argument, if these hints are made
 * available by the token; not all tokens expose these hints. */
typedef int (*gnutls_pkcs11_pin_callback_t)(void *userdata, int attempt,
                                    const char *slot_descr,
                                    const char *token_label,
                                    unsigned int flags,
                                    char *pin, size_t pin_max);

/**
 * @brief PKCS#11 certificate reference.
 */
struct gnutls_pkcs11_crt_st;
typedef struct gnutls_pkcs11_crt_st* gnutls_pkcs11_crt_t;



#define GNUTLS_PKCS11_FLAG_MANUAL 0 /* Manual loading of libraries */
#define GNUTLS_PKCS11_FLAG_AUTO 1 /* Automatically load libraries by reading /etc/gnutls/pkcs11.conf */

/* pkcs11.conf format:
 * load = /lib/xxx-pkcs11.so
 * load = /lib/yyy-pkcs11.so
 */

/**
 * @brief Initialize gnutls-pkcs11.
 * @param params	Misc values to use.
 * @return gnutls status.
 * @note gnutls-pkcs11 must be uninitialize.
 * @see gnutls_pkcs11_deinit()
 * @todo params is not implemented yet.
 *
 * params is in the format of:
 * name=value;name=value;
 */
int gnutls_pkcs11_init (unsigned int flags, const char* configfile);

/**
 * @brief Deinitialize gnutls-pkcs11.
 * @return gnutls status.
 */
void gnutls_pkcs11_deinit (void);

/**
 * @brief Set token prompt callback.
 * @param callback	Callback to use.
 * @param data		Data to use when calling callback.
 * @return gnutls status.
 */
void gnutls_pkcs11_set_token_function(gnutls_pkcs11_token_callback_t fn, void *userdata);

/**
 * @brief Set PIN prompt callback.
 * @param callback	Callback to use.
 * @param data		Data to use when calling callback.
 * @return gnutls status.
 */
void gnutls_pkcs11_set_pin_function (gnutls_pkcs11_pin_callback_t callback, void * const data);

/**
 * @brief Add PKCS#11 provider.
 * @param name		Library to load.
 * @param params	Misc provider parameters.
 * @return gnutls status.
 * @todo params is not implemented yet.
 *
 * params is in the format of:
 * name=value;name=value; 
 */
int gnutls_pkcs11_add_provider (const char * name, const char * params);

/**
 * @brief Free certificate reference.
 * @param certificate	Certificate reference to free.
 * @return gnutls stauts.
 */
int gnutls_pkcs11_crt_init ( gnutls_pkcs11_crt_t *certificate);

/**
 * @brief Deserialize a certificate reference.
 * @param serialized	Serialized certificate.
 * @param p_certificate	Certificate reference.
 * @return gnutls status.
 */
int gnutls_pkcs11_crt_import_url (gnutls_pkcs11_crt_t p_certificate, const char * url);

/**
 * @brief Serialize a certificate reference.
 * @param certificate	Certificate reference to serialize.
 * @param serialized	Serialize result (string). Use gnutls_free() to free it.
 * @return gnutls status.
 */
int gnutls_pkcs11_crt_export_url (gnutls_pkcs11_crt_t certificate, char** url);

/**
 * @brief Free certificate reference.
 * @param certificate	Certificate reference to free.
 * @return gnutls stauts.
 */
void gnutls_pkcs11_crt_deinit ( gnutls_pkcs11_crt_t certificate);

/**
 * @brief Release array of certificate references.
 * @param certificates	Array to free.
 * @param ncertificates	Array size.
 * @return gnutls status.
 */
int gnutls_pkcs11_crt_list_deinit (gnutls_pkcs11_crt_t * certificates, const unsigned int ncertificates);

typedef enum {
	GNUTLS_PKCS11_CRT_ID_HEX=1,
	GNUTLS_PKCS11_CRT_LABEL,
	GNUTLS_PKCS11_CRT_TOKEN_LABEL,
	GNUTLS_PKCS11_CRT_TOKEN_SERIAL,
	GNUTLS_PKCS11_CRT_TOKEN_MANUFACTURER,
	GNUTLS_PKCS11_CRT_TOKEN_MODEL,
	GNUTLS_PKCS11_CRT_ID,
} gnutls_pkcs11_cert_info_t;

int gnutls_pkcs11_crt_get_info(gnutls_pkcs11_crt_t crt, gnutls_pkcs11_cert_info_t itype, void* output, size_t* output_size);

typedef enum {
	GNUTLS_PKCS11_CRT_ATTR_ALL=1,
	GNUTLS_PKCS11_CRT_ATTR_TRUSTED, /* marked as trusted */
	GNUTLS_PKCS11_CRT_ATTR_WITH_PK, /* with corresponding private key */
} gnutls_pkcs11_crt_attr_t;

/* token info */
typedef enum {
	GNUTLS_PKCS11_TOKEN_LABEL,
	GNUTLS_PKCS11_TOKEN_SERIAL,
	GNUTLS_PKCS11_TOKEN_MANUFACTURER,
	GNUTLS_PKCS11_TOKEN_MODEL,
} gnutls_pkcs11_token_info_t;

int gnutls_pkcs11_token_get_url (unsigned int seq, char** url);
int gnutls_pkcs11_token_get_info(const char* url, gnutls_pkcs11_token_info_t, void* output, size_t *output_size);
/**
 * @brief Enumerate available certificates.
 * @param p_list	Location to store the list.
 * @param n_list	Location to store end list length.
 * @param url		Enumerate only certificates found in token(s) pointed by url
 * @param attributes Only export certificates that match this attribute
 * @return gnutls status.
 * @note the p_list is should not be initialized.
 */
int gnutls_pkcs11_crt_list_import_url (gnutls_pkcs11_crt_t * p_list, unsigned int *const n_list, const char* url, gnutls_pkcs11_crt_attr_t flags);

int gnutls_x509_crt_import_pkcs11( gnutls_x509_crt_t crt, gnutls_pkcs11_crt_t pkcs11_crt);
int gnutls_x509_crt_import_pkcs11_url( gnutls_x509_crt_t crt, const char* url);

/**
 * @brief Return the type of the certificate
 * @param certificate	Certificate reference.
 * @return gnutls status.
 */
gnutls_certificate_type_t gnutls_pkcs11_crt_get_type (gnutls_pkcs11_crt_t certificate);

int gnutls_x509_crt_list_import_pkcs11 (gnutls_x509_crt_t * certs,
                                   unsigned int cert_max,
                                   gnutls_pkcs11_crt_t * const pkcs11_certs,
                                   unsigned int flags);


/* private key functions...*/
int gnutls_pkcs11_privkey_init (gnutls_pkcs11_privkey_t * key);
void gnutls_pkcs11_privkey_deinit (gnutls_pkcs11_privkey_t key);
int gnutls_pkcs11_privkey_get_pk_algorithm (gnutls_pkcs11_privkey_t key, unsigned int* bits);
int gnutls_pkcs11_privkey_get_info(gnutls_pkcs11_privkey_t crt, gnutls_pkcs11_cert_info_t itype, void* output, size_t* output_size);
int gnutls_pkcs11_privkey_import_url (gnutls_pkcs11_privkey_t key,
				  const char* url);

int
gnutls_pkcs11_privkey_sign_data(gnutls_pkcs11_privkey_t signer,
				gnutls_digest_algorithm_t hash,
				unsigned int flags,
				const gnutls_datum_t * data,
				gnutls_datum_t * signature);
int gnutls_pkcs11_privkey_sign_hash (gnutls_pkcs11_privkey_t key,
				 const gnutls_datum_t * hash,
				 gnutls_datum_t * signature);
int
gnutls_pkcs11_privkey_decrypt_data(gnutls_pkcs11_privkey_t key,
				unsigned int flags, const gnutls_datum_t * ciphertext,
				gnutls_datum_t * plaintext);
int gnutls_pkcs11_privkey_export_url (gnutls_pkcs11_privkey_t key, char ** url);

/** @} */

#endif
