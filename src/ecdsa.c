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

#include "system.h"

#define TINC_ECDSA_INTERNAL
typedef struct {
	struct ecdsa_operations *ops;
	void *key;
} ecdsa_t;

#include "logger.h"
#include "ecdsa.h"
#include "utils.h"
#include "xalloc.h"

extern struct ecdsa_operations openssl_ecdsa_operations;
extern struct ecdsa_operations ed25519_ecdsa_operations;

// Get and set ECDSA keys
//

static ecdsa_t *ecdsa_set_public_key(const char *pubkey, int len) {
	ecdsa_t *ecdsa = xzalloc(sizeof(*ecdsa));

	if(len == 32) {
		// ed25519
		ecdsa->ops = &ed25519_ecdsa_operations;
	} else {
		// openssl
		ecdsa->ops = &openssl_ecdsa_operations;
	}

	ecdsa->key = ecdsa->ops->set_public_key(pubkey, len);

	if(ecdsa->key == NULL) {
		free(ecdsa);
		ecdsa = NULL;
	}

	return ecdsa;
}

ecdsa_t *ecdsa_set_base64_public_key(const char *p) {
	int len = strlen(p);
	char pubkey[len / 4 * 3 + 3];

	len = b64decode(p, pubkey, len);

	if(!len) {
		logger(DEBUG_ALWAYS, LOG_DEBUG, "Invalid base64 data in conf file\n");
		return NULL;
	}

	return ecdsa_set_public_key(pubkey, len);
}

char *ecdsa_get_base64_public_key(ecdsa_t *ecdsa) {
	int len;
	char *pubkey = ecdsa->ops->get_public_key(ecdsa->key, &len);
	char *base64 = xmalloc(len * 4 / 3 + 5);
	b64encode(pubkey, base64, len);

	free(pubkey);

	return base64;
}

ecdsa_t *ecdsa_read_pem_public_key(int keytype, FILE *fp) {
	struct ecdsa_operations *ops;

	switch(keytype) {
	case SPTPS_KEY_ED25519:
		ops = &ed25519_ecdsa_operations;
		break;

	case SPTPS_KEY_ECDSA:
		ops = &openssl_ecdsa_operations;
		break;

	default:
		return NULL;
	}

	ecdsa_t *ecdsa = xzalloc(sizeof(*ecdsa));
	ecdsa->ops = ops;
	ecdsa->key = ops->read_pem_public_key(fp);

	if(ecdsa->key == NULL) {
		free(ecdsa);
		ecdsa = NULL;
	}

	return ecdsa;
}

ecdsa_t *ecdsa_read_pem_private_key(int keytype, FILE *fp) {
	struct ecdsa_operations *ops;

	switch(keytype) {
	case SPTPS_KEY_ED25519:
		ops = &ed25519_ecdsa_operations;
		break;

	case SPTPS_KEY_ECDSA:
		ops = &openssl_ecdsa_operations;
		break;

	default:
		return NULL;
	}

	ecdsa_t *ecdsa = xzalloc(sizeof(*ecdsa));
	ecdsa->ops = ops;
	ecdsa->key = ops->read_pem_private_key(fp);

	if(ecdsa->key == NULL) {
		free(ecdsa);
		ecdsa = NULL;
	}

	return ecdsa;
}

bool ecdsa_write_pem_public_key(ecdsa_t *ecdsa, FILE *fp) {
	return ecdsa->ops->write_pem_public_key(ecdsa->key, fp);
}

bool ecdsa_write_pem_private_key(ecdsa_t *ecdsa, FILE *fp) {
	return ecdsa->ops->write_pem_private_key(ecdsa->key, fp);
}

size_t ecdsa_size(ecdsa_t *ecdsa) {
	return ecdsa->ops->size(ecdsa->key);
}

bool ecdsa_sign(ecdsa_t *ecdsa, const void *in, size_t len, void *sig) {
	return ecdsa->ops->sign(ecdsa->key, in, len, sig);
}

bool ecdsa_verify(ecdsa_t *ecdsa, const void *in, size_t len, const void *sig) {
	return ecdsa->ops->verify(ecdsa->key, in, len, sig);
}

bool ecdsa_active(ecdsa_t *ecdsa) {
	return ecdsa && ecdsa->key;
}

void ecdsa_free(ecdsa_t *ecdsa) {
	if(ecdsa != NULL) {
		ecdsa->ops->free(ecdsa->key);
		free(ecdsa);
	}
}

int ecdsa_keytype(ecdsa_t *ecdsa) {
	int keytype = SPTPS_KEY_NONE;

	if(ecdsa != NULL) {
		if(ecdsa->ops == &openssl_ecdsa_operations) {
			keytype = SPTPS_KEY_ECDSA;
		} else if(ecdsa->ops == &ed25519_ecdsa_operations) {
			keytype = SPTPS_KEY_ED25519;
		}
	}

	return keytype;
}

ecdsa_t *ecdsa_generate(int keytype) {
	struct ecdsa_operations *ops;

	switch(keytype) {
	case SPTPS_KEY_ED25519:
		ops = &ed25519_ecdsa_operations;
		break;

	case SPTPS_KEY_ECDSA:
		ops = &openssl_ecdsa_operations;
		break;

	default:
		return NULL;
	}

	ecdsa_t *ecdsa = xzalloc(sizeof(*ecdsa));
	ecdsa->ops = ops;
	ecdsa->key = ops->generate();

	if(ecdsa->key == NULL) {
		free(ecdsa);
		ecdsa = NULL;
	}

	return ecdsa;
}
