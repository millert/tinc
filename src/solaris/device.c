/*
    device.c -- Interaction with Solaris tun device
    Copyright (C) 2001-2005 Ivo Timmermans,
                  2002-2010 OpenVPN Technologies, Inc. <sales@openvpn.net>
                  2001-2014 Guus Sliepen <guus@tinc-vpn.org>

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

#include <sys/stropts.h>
#include <sys/sockio.h>
#include <assert.h>
#include <stropts.h>

#include "../async_pool.h"
#include "../conf.h"
#include "../device.h"
#include "../logger.h"
#include "../names.h"
#include "../net.h"
#include "../route.h"
#include "../utils.h"
#include "../tinycthread.h"
#include "../xalloc.h"

#ifndef TUNNEWPPA
#warning Missing net/if_tun.h, using hardcoded value for TUNNEWPPA
#define TUNNEWPPA       (('T'<<16) | 0x0001)
#endif

#define DEFAULT_TUN_DEVICE "/dev/tun"
#define DEFAULT_TAP_DEVICE "/dev/tap"
#define IP_DEVICE "/dev/udp"

static enum {
	DEVICE_TYPE_TUN,
	DEVICE_TYPE_TAP,
} device_type = DEVICE_TYPE_TUN;

#define ASYNC_DEVICE_QUEUE_LENGTH 128

bool active;
thrd_t thrd;
async_pool_t *device_read_pool;
int device_fd = -1;
int device_pipe[2] = { -1, -1 };
int real_fd = -1;
static int ip_fd = -1;
char *device = NULL;
char *iface = NULL;
static const char *device_info = NULL;

static bool read_packet(vpn_packet_t *packet) {
	int result;
	struct strbuf sbuf;
	int f = 0;

	switch(device_type) {
	case DEVICE_TYPE_TUN:
		sbuf.maxlen = MTU - 14;
		sbuf.buf = (char *)DATA(packet) + 14;

		if((result = getmsg(real_fd, NULL, &sbuf, &f)) < 0) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Error while reading from %s %s: %s", device_info, device, strerror(errno));
			return false;
		}

		switch(DATA(packet)[14] >> 4) {
		case 4:
			DATA(packet)[12] = 0x08;
			DATA(packet)[13] = 0x00;
			break;

		case 6:
			DATA(packet)[12] = 0x86;
			DATA(packet)[13] = 0xDD;
			break;

		default:
			logger(DEBUG_TRAFFIC, LOG_ERR, "Unknown IP version %d while reading packet from %s %s", DATA(packet)[14] >> 4, device_info, device);
			return false;
		}

		memset(DATA(packet), 0, 12);
		packet->len = sbuf.len + 14;
		break;

	case DEVICE_TYPE_TAP:
		sbuf.maxlen = MTU;
		sbuf.buf = (char *)DATA(packet);

		if((result = getmsg(real_fd, NULL, &sbuf, &f)) < 0) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Error while reading from %s %s: %s", device_info, device, strerror(errno));
			return false;
		}

		packet->len = sbuf.len;
		break;

	default:
		abort();
	}

	logger(DEBUG_TRAFFIC, LOG_DEBUG, "Read packet of %d bytes from %s", packet->len, device_info);

	return true;
}

static bool write_packet(vpn_packet_t *packet) {
	logger(DEBUG_TRAFFIC, LOG_DEBUG, "Writing packet of %d bytes to %s", packet->len, device_info);

	struct strbuf sbuf;

	switch(device_type) {
	case DEVICE_TYPE_TUN:
		sbuf.len = packet->len - 14;
		sbuf.buf = (char *)DATA(packet) + 14;

		if(putmsg(real_fd, NULL, &sbuf, 0) < 0) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Can't write to %s %s: %s", device_info, device, strerror(errno));
			return false;
		}

		break;

	case DEVICE_TYPE_TAP:
		sbuf.len = packet->len;
		sbuf.buf = (char *)DATA(packet);

		if(putmsg(real_fd, NULL, &sbuf, 0) < 0) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Can't write to %s %s: %s", device_info, device, strerror(errno));
			return false;
		}

		break;

	default:
		abort();
	}

	return true;
}

static int read_thread(void *arg) {
#if 0
	fd_set readfds;

	FD_ZERO(&readfds);
	FD_SET(real_fd, &readfds);

	/* Wait for TUN/TAP to be ready or we get EIO on macOS. */
	for(;;) {
		int n = select(real_fd + 1, &readfds, NULL, NULL, NULL);

		if(n != -1 || errno != EINTR) {
			break;
		}
	}

#endif

	while(active) {
		vpn_packet_t *packet = async_pool_get(device_read_pool);

		packet->offset = DEFAULT_PACKET_OFFSET;
		packet->priority = 0;

		if(read_packet(packet)) {
			async_pool_put(device_read_pool, packet);
			static const uint64_t one = 1;
			assert(write(device_pipe[1], &one, sizeof(one)) == sizeof(one));
		} else {
			abort();
		}
	}

	return 0;
}

static bool setup_device(void) {
	char *type;

	if(pipe(device_pipe) == -1) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not create pipe %s", strerror(errno));
		return false;
	}

	for(int i = 0; i < 2; i++) {
		int flags = fcntl(device_pipe[i], F_GETFL);

		if(fcntl(device_pipe[i], F_SETFL, flags | O_NONBLOCK) == -1) {
			logger(DEBUG_ALWAYS, LOG_ERR, "fcntl for %s: %s", device, strerror(errno));
			return false;
		}

		flags = fcntl(device_pipe[i], F_GETFL);

		if(fcntl(device_pipe[i], F_SETFL, flags | O_NONBLOCK) == -1) {
			logger(DEBUG_ALWAYS, LOG_ERR, "fcntl for %s: %s", device, strerror(errno));
			return false;
		}

#ifdef FD_CLOEXEC
		fcntl(device_pipe[i], F_SETFD, FD_CLOEXEC);
#endif
	}

	device_fd = device_pipe[0];

	device_read_pool = async_pool_alloc(ASYNC_DEVICE_QUEUE_LENGTH, sizeof(vpn_packet_t), NULL);

	if(!get_config_string(lookup_config(config_tree, "Device"), &device)) {
		if(routing_mode == RMODE_ROUTER) {
			device = xstrdup(DEFAULT_TUN_DEVICE);
		} else {
			device = xstrdup(DEFAULT_TAP_DEVICE);
		}
	}

	if(get_config_string(lookup_config(config_tree, "DeviceType"), &type)) {
		if(!strcasecmp(type, "tun"))
			/* use default */;
		else if(!strcasecmp(type, "tap")) {
			device_type = DEVICE_TYPE_TAP;
		} else {
			logger(DEBUG_ALWAYS, LOG_ERR, "Unknown device type %s!", type);
			return false;
		}
	} else {
		if(strstr(device, "tap") || routing_mode != RMODE_ROUTER) {
			device_type = DEVICE_TYPE_TAP;
		}
	}

	if(device_type == DEVICE_TYPE_TUN) {
		device_info = "Solaris tun device";
	} else {
		device_info = "Solaris tap device";
	}

	/* The following is black magic copied from OpenVPN. */

	if((ip_fd = open(IP_DEVICE, O_RDWR, 0)) < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not open %s: %s\n", IP_DEVICE, strerror(errno));
		return false;
	}

	if((real_fd = open(device, O_RDWR, 0)) < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not open %s: %s\n", device, strerror(errno));
		return false;
	}

	/* Get unit number. */

	char *ptr = device;
	get_config_string(lookup_config(config_tree, "Interface"), &ptr);

	while(*ptr && !isdigit(*ptr)) {
		ptr++;
	}

	int ppa = atoi(ptr);

	/* Assign a new PPA and get its unit number. */

	struct strioctl strioc_ppa = {
		.ic_cmd = TUNNEWPPA,
		.ic_len = sizeof(ppa),
		.ic_dp = (char *) &ppa,
	};

	if(!*ptr) { /* no number given, try dynamic */
		bool found = false;

		while(!found && ppa < 64) {
			int new_ppa = ioctl(real_fd, I_STR, &strioc_ppa);

			if(new_ppa >= 0) {
				ppa = new_ppa;
				found = true;
				break;
			}

			ppa++;
		}

		if(!found) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Could not find free PPA for %s %s!", device_info, device);
			return false;
		}
	} else { /* try this particular one */
		if((ppa = ioctl(real_fd, I_STR, &strioc_ppa)) < 0) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Could not assign PPA %d for %s %s!", ppa, device_info, device);
			return false;
		}
	}

	int if_fd;

	if((if_fd = open(device, O_RDWR, 0)) < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not open %s: %s\n", device, strerror(errno));
		return false;
	}

	if(ioctl(if_fd, I_PUSH, "ip") < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not push IP module onto %s %s!", device_info, device);
		return false;
	}

	xasprintf(&iface, "%s%d", device_type == DEVICE_TYPE_TUN ? "tun" : "tap", ppa);

	{
		/* Remove muxes just in case they are left over from a crashed tincd */
		struct lifreq ifr = {};
		strncpy(ifr.lifr_name, iface, sizeof(ifr.lifr_name));

		if(ioctl(ip_fd, SIOCGLIFMUXID, &ifr) >= 0) {
			int muxid = ifr.lifr_arp_muxid;
			ioctl(ip_fd, I_PUNLINK, muxid);
			muxid = ifr.lifr_ip_muxid;
			ioctl(ip_fd, I_PUNLINK, muxid);
		}
	}

	if(device_type == DEVICE_TYPE_TUN) {
		/* Assign ppa according to the unit number returned by tun device */
		if(ioctl(if_fd, IF_UNITSEL, (char *)&ppa) < 0) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Could not set PPA %d on %s %s!", ppa, device_info, device);
			return false;
		}
	}

	int arp_fd = -1;

	if(device_type == DEVICE_TYPE_TAP) {
		struct lifreq ifr = {};

		if(ioctl(if_fd, SIOCGLIFFLAGS, &ifr) < 0) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Could not set flags on %s %s!", device_info, device);
			return false;
		}

		strncpy(ifr.lifr_name, iface, sizeof(ifr.lifr_name));
		ifr.lifr_ppa = ppa;

		/* Assign ppa according to the unit number returned by tun device */
		if(ioctl(if_fd, SIOCSLIFNAME, &ifr) < 0) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Could not set PPA %d on %s %s!", ppa, device_info, device);
			return false;
		}

		if(ioctl(if_fd, SIOCGLIFFLAGS, &ifr) < 0) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Could not set flags on %s %s!", device_info, device);
			return false;
		}

		/* Push arp module to if_fd */
		if(ioctl(if_fd, I_PUSH, "arp") < 0) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Could not push ARP module onto %s %s!", device_info, device);
			return false;
		}

		/* Pop any modules on the stream */
		while(true) {
			if(ioctl(ip_fd, I_POP, NULL) < 0) {
				break;
			}
		}

		/* Push arp module to ip_fd */
		if(ioctl(ip_fd, I_PUSH, "arp") < 0) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Could not push ARP module onto %s!", IP_DEVICE);
			return false;
		}

		/* Open arp_fd */
		if((arp_fd = open(device, O_RDWR, 0)) < 0) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Could not open %s: %s\n", device, strerror(errno));
			return false;
		}

		/* Push arp module to arp_fd */
		if(ioctl(arp_fd, I_PUSH, "arp") < 0) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Could not push ARP module onto %s %s!", device_info, device);
			return false;
		}

		/* Set ifname to arp */
		struct strioctl strioc_if = {
			.ic_cmd = SIOCSLIFNAME,
			.ic_len = sizeof(ifr),
			.ic_dp = (char *) &ifr,
		};

		if(ioctl(arp_fd, I_STR, &strioc_if) < 0) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Could not set ifname to %s %s", device_info, device);
			return false;
		}
	}

	int ip_muxid, arp_muxid;

	if((ip_muxid = ioctl(ip_fd, I_PLINK, if_fd)) < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not link %s %s to IP", device_info, device);
		return false;
	}

	if(device_type == DEVICE_TYPE_TAP) {
		if((arp_muxid = ioctl(ip_fd, I_PLINK, arp_fd)) < 0) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Could not link %s %s to ARP", device_info, device);
			return false;
		}

		close(arp_fd);
	}

	struct lifreq ifr = {};

	strncpy(ifr.lifr_name, iface, sizeof(ifr.lifr_name));

	ifr.lifr_ip_muxid = ip_muxid;

	if(device_type == DEVICE_TYPE_TAP) {
		ifr.lifr_arp_muxid = arp_muxid;
	}

	if(ioctl(ip_fd, SIOCSLIFMUXID, &ifr) < 0) {
		if(device_type == DEVICE_TYPE_TAP) {
			ioctl(ip_fd, I_PUNLINK, arp_muxid);
		}

		ioctl(ip_fd, I_PUNLINK, ip_muxid);
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not set multiplexor id for %s %s", device_info, device);
		return false;
	}

	close(if_fd);

#ifdef FD_CLOEXEC
	fcntl(real_fd, F_SETFD, FD_CLOEXEC);
	fcntl(ip_fd, F_SETFD, FD_CLOEXEC);
#endif

	logger(DEBUG_ALWAYS, LOG_INFO, "%s is a %s", device, device_info);

	active = true;

	if(thrd_create(&thrd, read_thread, NULL) != thrd_success) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not create tun/tap thread from %s: %s", device, strerror(errno));
		active = false;
		return false;
	}

	return true;
}

static void close_device(void) {
	if(iface) {
		struct lifreq ifr = {};
		strncpy(ifr.lifr_name, iface, sizeof(ifr.lifr_name));

		if(ioctl(ip_fd, SIOCGLIFMUXID, &ifr) >= 0) {
			int muxid = ifr.lifr_arp_muxid;
			ioctl(ip_fd, I_PUNLINK, muxid);
			muxid = ifr.lifr_ip_muxid;
			ioctl(ip_fd, I_PUNLINK, muxid);
		}
	}

	close(ip_fd);
	ip_fd = -1;
	close(real_fd);
	real_fd = -1;
	device_fd = -1;

	close(device_pipe[0]);
	close(device_pipe[1]);
	device_pipe[0] = -1;
	device_pipe[1] = -1;

	if(active) {
		active = false;
		thrd_join(thrd, NULL);
	}

	async_pool_free(device_read_pool);
	device_read_pool = NULL;

	free(device);
	device = NULL;
	free(iface);
	iface = NULL;
}

const devops_t os_devops = {
	.setup = setup_device,
	.close = close_device,
	.read = NULL,
	.write = write_packet,
};
