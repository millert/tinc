#ifndef TINC_ECDH_H
#define TINC_ECDH_H

/*
    ecdh.h -- header file for ecdh.c
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

#ifndef __TINC_ECDH_H__
#define __TINC_ECDH_H__

#ifndef TINC_ECDH_INTERNAL
typedef struct ecdh ecdh_t;
#endif

struct ecdh_operations {
	size_t (*size)(void);
	size_t (*shared_size)(void);
	void *(*generate_public)(void *pubkey);
	bool (*compute_shared)(void *ecdh, const void *pubkey, void *shared);
	void (*free)(void *ecdh);
};

extern ecdh_t *ecdh_alloc(int keytype) __attribute__((__malloc__));
extern bool ecdh_generate_public(ecdh_t *ecdh, void *pubkey);
extern bool ecdh_compute_shared(ecdh_t *ecdh, const void *pubkey, void *shared) __attribute__((__warn_unused_result__));
extern void ecdh_free(ecdh_t *ecdh);
extern size_t ecdh_size(ecdh_t *ecdh);
extern size_t ecdh_shared_size(ecdh_t *ecdh);

#endif
