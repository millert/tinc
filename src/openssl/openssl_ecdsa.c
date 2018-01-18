/*
    ecdsa.c -- ECDSA key handling
    Copyright (C) 2011-2013 Guus Sliepen <guus@tinc-vpn.org>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "../system.h"

#include <openssl/pem.h>
#include <openssl/err.h>

#include "../logger.h"
#include "../ecdsa.h"
#include "../utils.h"
#include "../xalloc.h"

// Get and set ECDSA keys
//
static void *openssl_ecdsa_set_public_key(const char *pubkey, int len) {
	const unsigned char *ppubkey = (const unsigned char *)pubkey;
	EC_KEY *ecdsa = EC_KEY_new_by_curve_name(NID_secp521r1);

	if(!ecdsa) {
		logger(DEBUG_ALWAYS, LOG_DEBUG, "EC_KEY_new_by_curve_name failed: %s", ERR_error_string(ERR_get_error(), NULL));
		return NULL;
	}

	if(!o2i_ECPublicKey(&ecdsa, &ppubkey, len)) {
		logger(DEBUG_ALWAYS, LOG_DEBUG, "o2i_ECPublicKey failed: %s", ERR_error_string(ERR_get_error(), NULL));
		EC_KEY_free(ecdsa);
		return NULL;
	}

	return ecdsa;
}

static char *openssl_ecdsa_get_public_key(void *ecdsa, int *len) {
	unsigned char *pubkey = NULL;
	*len = i2o_ECPublicKey(ecdsa, &pubkey);

	return (char *)pubkey;
}

// Generate ECDSA key

static void *openssl_ecdsa_generate(void) {
	EC_KEY *ecdsa = EC_KEY_new_by_curve_name(NID_secp521r1);

	if(!ecdsa || !EC_KEY_generate_key(ecdsa)) {
		fprintf(stderr, "Generating EC key failed: %s", ERR_error_string(ERR_get_error(), NULL));
		EC_KEY_free(ecdsa);
		return NULL;
	}

	EC_KEY_set_asn1_flag(ecdsa, OPENSSL_EC_NAMED_CURVE);
	EC_KEY_set_conv_form(ecdsa, POINT_CONVERSION_COMPRESSED);

	return ecdsa;
}

// Read PEM ECDSA keys

static void *openssl_ecdsa_read_pem_public_key(FILE *fp) {
	EC_KEY *ecdsa = PEM_read_EC_PUBKEY(fp, NULL, NULL, NULL);

	if(!ecdsa) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Unable to read ECDSA public key: %s", ERR_error_string(ERR_get_error(), NULL));
	}

	return ecdsa;
}

static void *openssl_ecdsa_read_pem_private_key(FILE *fp) {
	EC_KEY *ecdsa = PEM_read_ECPrivateKey(fp, NULL, NULL, NULL);

	if(!ecdsa) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Unable to read ECDSA private key: %s", ERR_error_string(ERR_get_error(), NULL));
	}

	return ecdsa;
}

// Write PEM ECDSA keys

static bool openssl_ecdsa_write_pem_public_key(void *v, FILE *fp) {
	EC_KEY *ecdsa = v;

	return PEM_write_EC_PUBKEY(fp, ecdsa);
}

static bool openssl_ecdsa_write_pem_private_key(void *v, FILE *fp) {
	EC_KEY *ecdsa = v;

	return PEM_write_ECPrivateKey(fp, ecdsa, NULL, NULL, 0, NULL, NULL);
}

static size_t openssl_ecdsa_size(void *v) {
	const EC_KEY *ecdsa = v;

	return ECDSA_size(ecdsa);
}

// TODO: standardise output format?

static bool openssl_ecdsa_sign(void *ecdsa, const void *in, size_t len, void *sig) {
	unsigned int siglen = ECDSA_size(ecdsa);

	unsigned char hash[SHA512_DIGEST_LENGTH];
	SHA512(in, len, hash);

	memset(sig, 0, siglen);

	if(!ECDSA_sign(0, hash, sizeof hash, sig, &siglen, ecdsa)) {
		logger(DEBUG_ALWAYS, LOG_DEBUG, "ECDSA_sign() failed: %s", ERR_error_string(ERR_get_error(), NULL));
		return false;
	}

	return true;
}

static bool openssl_ecdsa_verify(void *ecdsa, const void *in, size_t len, const void *sig) {
	unsigned int siglen = ECDSA_size(ecdsa);

	unsigned char hash[SHA512_DIGEST_LENGTH];
	SHA512(in, len, hash);

	if(!ECDSA_verify(0, hash, sizeof hash, sig, siglen, ecdsa)) {
		logger(DEBUG_ALWAYS, LOG_DEBUG, "ECDSA_verify() failed: %s", ERR_error_string(ERR_get_error(), NULL));
		return false;
	}

	return true;
}

static void openssl_ecdsa_free(void *ecdsa) {
	EC_KEY_free(ecdsa);
}

struct ecdsa_operations openssl_ecdsa_operations = {
	openssl_ecdsa_set_public_key,
	openssl_ecdsa_get_public_key,
	openssl_ecdsa_generate,
	openssl_ecdsa_read_pem_public_key,
	openssl_ecdsa_read_pem_private_key,
	openssl_ecdsa_write_pem_public_key,
	openssl_ecdsa_write_pem_private_key,
	openssl_ecdsa_size,
	openssl_ecdsa_sign,
	openssl_ecdsa_verify,
	openssl_ecdsa_free
};
