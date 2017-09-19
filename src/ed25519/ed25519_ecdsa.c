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

#include "ed25519.h"

typedef struct {
	uint8_t private[64];
	uint8_t public[32];
} ecdsa_impl_t;

#include "../logger.h"
#include "../crypto.h"
#include "../ecdsa.h"
#include "../utils.h"
#include "../xalloc.h"

// Get and set ECDSA keys
//
static void *ed25519_ecdsa_set_public_key(const char *pubkey, int len) {
	if(len != 32) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Invalid format of public key! len = %d", len);
		return 0;
	}
	ecdsa_impl_t *ecdsa = xzalloc(sizeof(*ecdsa));
	memcpy(ecdsa->public, pubkey, len);

	return ecdsa;
}

static char *ed25519_ecdsa_get_public_key(void *v, int *len) {
	ecdsa_impl_t *ecdsa = v;
	char *pubkey = xzalloc(sizeof(ecdsa->public));
	memcpy(pubkey, ecdsa->public, sizeof(ecdsa->public));
	*len = sizeof(ecdsa->public);

	return pubkey;
}

// Generate ECDSA key

static void *ed25519_ecdsa_generate(void) {
	ecdsa_impl_t *ecdsa = xzalloc(sizeof(*ecdsa));

	uint8_t seed[32];
	randomize(seed, sizeof(seed));
	ed25519_create_keypair(ecdsa->public, ecdsa->private, seed);

	return ecdsa;
}

// Read PEM ECDSA keys

static bool read_pem(FILE *fp, const char *type, void *buf, size_t size) {
	char line[1024];
	bool data = false;
	size_t typelen = strlen(type);

	while(fgets(line, sizeof(line), fp)) {
		if(!data) {
			if(strncmp(line, "-----BEGIN ", 11)) {
				continue;
			}

			if(strncmp(line + 11, type, typelen)) {
				continue;
			}

			data = true;
			continue;
		}

		if(!strncmp(line, "-----END ", 9)) {
			break;
		}

		size_t linelen = strcspn(line, "\r\n");
		size_t len = b64decode(line, line, linelen);

		if(!len) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Invalid base64 data in PEM file\n");
			errno = EINVAL;
			return false;
		}

		if(len > size) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Too much base64 data in PEM file\n");
			errno = EINVAL;
			return false;
		}

		memcpy(buf, line, len);
		buf += len;
		size -= len;
	}

	if(size) {
		if(data) {
			errno = EINVAL;
			logger(DEBUG_ALWAYS, LOG_ERR, "Too little base64 data in PEM file\n");
		} else {
			errno = ENOENT;
		}

		return false;
	}

	return true;
}

static void *ed25519_ecdsa_read_pem_public_key(FILE *fp) {
	ecdsa_impl_t *ecdsa = xzalloc(sizeof(*ecdsa));
	if(read_pem(fp, "ED25519 PUBLIC KEY", ecdsa->public, sizeof(ecdsa->public))) {
		return ecdsa;
	}

	free(ecdsa);
	return 0;
}

static void *ed25519_ecdsa_read_pem_private_key(FILE *fp) {
	ecdsa_impl_t *ecdsa = xmalloc(sizeof(*ecdsa));
	if(read_pem(fp, "ED25519 PRIVATE KEY", ecdsa->private, sizeof(*ecdsa))) {
		return ecdsa;
	}

	free(ecdsa);
	return 0;
}

// Write PEM ECDSA keys

static bool write_pem(FILE *fp, const char *type, void *buf, size_t size) {
	fprintf(fp, "-----BEGIN %s-----\n", type);

	char base64[65];
	while(size) {
		size_t todo = size > 48 ? 48 : size;
		b64encode(buf, base64, todo);
		fprintf(fp, "%s\n", base64);
		buf += todo;
		size -= todo;
	}

	fprintf(fp, "-----END %s-----\n", type);
	return !ferror(fp);
}

static bool ed25519_ecdsa_write_pem_public_key(void *v, FILE *fp) {
	ecdsa_impl_t *ecdsa = v;
	return write_pem(fp, "ED25519 PUBLIC KEY", ecdsa->public, sizeof(ecdsa->public));
}

static bool ed25519_ecdsa_write_pem_private_key(void *v, FILE *fp) {
	ecdsa_impl_t *ecdsa = v;
	return write_pem(fp, "ED25519 PRIVATE KEY", ecdsa->private, sizeof(*ecdsa));
}

static size_t ed25519_ecdsa_size(void *v) {
	return 64;
}

// TODO: standardise output format?

static bool ed25519_ecdsa_sign(void *v, const void *in, size_t len, void *sig) {
	ecdsa_impl_t *ecdsa = v;
	ed25519_sign(sig, in, len, ecdsa->public, ecdsa->private);
	return true;
}

static bool ed25519_ecdsa_verify(void *v, const void *in, size_t len, const void *sig) {
	ecdsa_impl_t *ecdsa = v;
	return ed25519_verify(sig, in, len, ecdsa->public);
}

static void ed25519_ecdsa_free(void *v) {
	ecdsa_impl_t *ecdsa = v;
	free(ecdsa);
}

struct ecdsa_operations ed25519_ecdsa_operations = {
	ed25519_ecdsa_set_public_key,
	ed25519_ecdsa_get_public_key,
	ed25519_ecdsa_generate,
	ed25519_ecdsa_read_pem_public_key,
	ed25519_ecdsa_read_pem_private_key,
	ed25519_ecdsa_write_pem_public_key,
	ed25519_ecdsa_write_pem_private_key,
	ed25519_ecdsa_size,
	ed25519_ecdsa_sign,
	ed25519_ecdsa_verify,
	ed25519_ecdsa_free
};
