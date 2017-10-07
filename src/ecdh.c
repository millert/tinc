/*
    ecdh.c -- Diffie-Hellman key exchange handling
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

#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/obj_mac.h>

#define TINC_ECDH_INTERNAL
typedef struct ecdh {
	struct ecdh_operations *ops;
	void *key;
} ecdh_t;

#include "ecdh.h"
#include "ecdsa.h" /* For SPTPS_KEY_* */
#include "logger.h"
#include "utils.h"
#include "xalloc.h"

extern struct ecdh_operations openssl_ecdh_operations;
extern struct ecdh_operations ed25519_ecdh_operations;

ecdh_t *ecdh_alloc(int keytype) {
	struct ecdh_operations *ops;

	switch(keytype) {
	case SPTPS_KEY_ED25519:
		ops = &ed25519_ecdh_operations;
		break;

	case SPTPS_KEY_ECDSA:
		ops = &openssl_ecdh_operations;
		break;

	default:
		return NULL;
	}

	ecdh_t *ecdh = xmalloc(sizeof(*ecdh));
	ecdh->ops = ops;
	ecdh->key = NULL;

	return ecdh;
}

size_t ecdh_size(ecdh_t *ecdh) {
	return ecdh->ops->size();
}

size_t ecdh_shared_size(ecdh_t *ecdh) {
	return ecdh->ops->shared_size();
}

bool ecdh_generate_public(ecdh_t *ecdh, void *pubkey) {
	if(!ecdh) {
		logger(DEBUG_ALWAYS, LOG_ERR, "%s called with unallocated ecdh", __func__);
		return false;
	}

	ecdh->key = ecdh->ops->generate_public(pubkey);
	return ecdh->key != NULL;
}

bool ecdh_compute_shared(ecdh_t *ecdh, const void *pubkey, void *shared) {
	if(!ecdh) {
		logger(DEBUG_ALWAYS, LOG_ERR, "%s called with unallocated ecdh", __func__);
		return false;
	}

	bool ret = ecdh->ops->compute_shared(ecdh->key, pubkey, shared);
	free(ecdh);
	return ret;
}

void ecdh_free(ecdh_t *ecdh) {
	if(ecdh) {
		ecdh->ops->free(ecdh->key);
		free(ecdh);
	}
}
