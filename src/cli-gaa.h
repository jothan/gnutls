
#line 104 "gaa.skel"
/* GAA HEADER */
#ifndef GAA_HEADER_POKY
#define GAA_HEADER_POKY

typedef struct _gaainfo gaainfo;

struct _gaainfo
{
#line 130 "cli.gaa"
	char *rest_args;
#line 122 "cli.gaa"
	int insecure;
#line 119 "cli.gaa"
	char *port;
#line 116 "cli.gaa"
	char *opaque_prf_input;
#line 113 "cli.gaa"
	char *psk_key;
#line 110 "cli.gaa"
	char *psk_username;
#line 107 "cli.gaa"
	char *srp_passwd;
#line 104 "cli.gaa"
	char *srp_username;
#line 101 "cli.gaa"
	char *x509_certfile;
#line 98 "cli.gaa"
	char *x509_keyfile;
#line 95 "cli.gaa"
	char *pgp_subkey;
#line 92 "cli.gaa"
	char *pgp_certfile;
#line 89 "cli.gaa"
	char *pgp_keyring;
#line 86 "cli.gaa"
	char *pgp_keyfile;
#line 83 "cli.gaa"
	char *x509_crlfile;
#line 80 "cli.gaa"
	char *x509_cafile;
#line 77 "cli.gaa"
	char *priorities;
#line 74 "cli.gaa"
	char **ctype;
#line 73 "cli.gaa"
	int nctype;
#line 70 "cli.gaa"
	char **kx;
#line 69 "cli.gaa"
	int nkx;
#line 66 "cli.gaa"
	char **macs;
#line 65 "cli.gaa"
	int nmacs;
#line 62 "cli.gaa"
	char **comp;
#line 61 "cli.gaa"
	int ncomp;
#line 58 "cli.gaa"
	char **proto;
#line 57 "cli.gaa"
	int nproto;
#line 54 "cli.gaa"
	char **ciphers;
#line 53 "cli.gaa"
	int nciphers;
#line 50 "cli.gaa"
	int verbose;
#line 47 "cli.gaa"
	int record_size;
#line 44 "cli.gaa"
	int print_cert;
#line 41 "cli.gaa"
	int disable_extensions;
#line 38 "cli.gaa"
	int fingerprint;
#line 35 "cli.gaa"
	int fmtder;
#line 32 "cli.gaa"
	int crlf;
#line 29 "cli.gaa"
	int dtls;
#line 26 "cli.gaa"
	int starttls;
#line 23 "cli.gaa"
	int noticket;
#line 20 "cli.gaa"
	int rehandshake;
#line 17 "cli.gaa"
	int resume;
#line 14 "cli.gaa"
	int debug;

#line 114 "gaa.skel"
};

#ifdef __cplusplus
extern "C"
{
#endif

    int gaa(int argc, char *argv[], gaainfo *gaaval);

    void gaa_help(void);
    
    int gaa_file(const char *name, gaainfo *gaaval);
    
#ifdef __cplusplus
}
#endif


#endif
