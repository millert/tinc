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

#include "../system.h"

#include "ed25519.h"

#define ECDH_SIZE 32
#define ECDH_SHARED_SIZE 32

#include "../crypto.h"
#include "../ecdh.h"
#include "../xalloc.h"

typedef struct {
	uint8_t private[64];
} ecdh_impl_t;

static size_t ed25519_ecdh_size(void) {
	return ECDH_SIZE;
}

static size_t ed25519_ecdh_shared_size(void) {
	return ECDH_SHARED_SIZE;
}

static void *ed25519_ecdh_generate_public(void *pubkey) {
	ecdh_impl_t *ecdh = xzalloc(sizeof(*ecdh));

	uint8_t seed[32];
	randomize(seed, sizeof(seed));
	ed25519_create_keypair(pubkey, ecdh->private, seed);

	return ecdh;
}

static bool ed25519_ecdh_compute_shared(void *v, const void *pubkey, void *shared) {
	ecdh_impl_t *ecdh = v;
	ed25519_key_exchange(shared, pubkey, ecdh->private);
	free(ecdh);
	return true;
}

static void ed25519_ecdh_free(void *v) {
	ecdh_impl_t *ecdh = v;
	free(ecdh);
}

struct ecdh_operations ed25519_ecdh_operations = {
	ed25519_ecdh_size,
	ed25519_ecdh_shared_size,
	ed25519_ecdh_generate_public,
	ed25519_ecdh_compute_shared,
	ed25519_ecdh_free
};
