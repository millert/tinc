/*
    sptps_speed.c -- SPTPS benchmark
    Copyright (C) 2013-2014 Guus Sliepen <guus@tinc-vpn.org>

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
#include "utils.h"

#include <getopt.h>

#include "crypto.h"
#include "ecdh.h"
#include "ecdsa.h"
#include "sptps.h"

// Symbols necessary to link with logger.o
bool send_request(void *c, const char *msg, ...) {
	return false;
}
struct list_t *connection_list = NULL;
bool send_meta(void *c, const char *msg, int len) {
	return false;
}
char *logfilename = NULL;
bool do_detach = false;
struct timeval now;

static bool send_data(void *handle, uint8_t type, const void *data, size_t len) {
	int fd = *(int *)handle;
	size_t nsent = send(fd, data, len, 0);

	if(nsent != len) {
		if(nsent == (size_t) - 1) {
			fprintf(stderr, "%s: send: %s\n", __func__, sockstrerror(sockerrno));
		} else {
			fprintf(stderr, "%s: short send\n", __func__);
		}

		return false;
	}

	return true;
}

static bool receive_record(void *handle, uint8_t type, const void *data, uint16_t len) {
	return true;
}

static void receive_data(sptps_t *sptps) {
	char buf[4096], *bufp = buf;
	int fd = *(int *)sptps->handle;
	size_t len = recv(fd, buf, sizeof(buf), 0);

	if(len == (size_t) - 1) {
		fprintf(stderr, "%s: recv: %s\n", __func__, sockstrerror(sockerrno));
		return;
	}

	while(len) {
		size_t done = sptps_receive_data(sptps, bufp, len);

		if(!done) {
			abort();
		}

		bufp += done;
		len -= done;
	}
}

struct timespec start;
struct timespec end;
double elapsed;
double rate;
unsigned int count;

static void clock_start() {
	count = 0;
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
}

static bool clock_countto(double seconds) {
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end);
	elapsed = end.tv_sec + end.tv_nsec * 1e-9 - start.tv_sec - start.tv_nsec * 1e-9;

	if(elapsed < seconds) {
		return ++count;
	}

	rate = count / elapsed;
	return false;
}

static struct option const long_options[] = {
	{"cipher", required_argument, NULL, 'c'},
	{"help", no_argument, NULL, 'h'},
	{"key-type", required_argument, NULL, 'k'},
	{NULL, 0, NULL, 0}
};

const char *program_name;

static void usage() {
	fprintf(stderr, "Usage: %s [options] my_ecdsa_key_file his_ecdsa_key_file [host] port\n\n", program_name);
	fprintf(stderr, "Valid options are:\n"
	        "  -c, --cipher    Cipher, either aes-256-gcm or chacha20-poly1305.\n"
	        "  -k, --key-type  Key type, either ecdsa or ed25519.\n"
	        "  -h, --help      Display this help and exit.\n"
	        "\n");
	fprintf(stderr, "Report bugs to tinc@tinc-vpn.org.\n");
}

#ifdef HAVE_MINGW
static int set_nonblock(int sock) {
#ifdef O_NONBLOCK
	int flags = fcntl(sock, F_GETFL);

	flags |= O_NONBLOCK;

	if(fcntl(sock, F_SETFL, flags) == -1) {
		return -1;
	}

#else
	unsigned long arg = 1;

	if(ioctlsocket(sock, FIONBIO, &arg) != 0) {
		return -1;
	}

#endif
	return 0;
}

static int unset_nonblock(int sock) {
#ifdef O_NONBLOCK
	int flags = fcntl(sock, F_GETFL);

	flags &= ~O_NONBLOCK;

	if(fcntl(sock, F_SETFL, flags) == -1) {
		return -1;
	}

#else
	unsigned long arg = 0;

	if(ioctlsocket(sock, FIONBIO, &arg) != 0) {
		return -1;
	}

#endif
	return 0;
}

#define LOCAL_PORT      65432

#ifdef HAVE_MINGW
# define CONNECT_IN_PROGRESS     WSAEWOULDBLOCK
#else
# define CONNECT_IN_PROGRESS     EINPROGRESS
#endif

/* Connect fd[0] <-> fd[1], TCP */
static int connect_sockets_tcp(int *fd, struct sockaddr_in *sin) {
	if(set_nonblock(fd[0])) {
		fprintf(stderr, "Could not make socket nonblocking: %s\n", sockstrerror(sockerrno));
		return -1;
	}

	if(listen(fd[1], 1) == -1) {
		fprintf(stderr, "Could not listen: %s\n", sockstrerror(sockerrno));
		return -1;
	}

	if(connect(fd[0], (struct sockaddr *)sin, sizeof(*sin)) == -1) {
		if(sockerrno != CONNECT_IN_PROGRESS) {
			fprintf(stderr, "Could not connect sockets: %s\n", sockstrerror(sockerrno));
			return -1;
		}
	}

	socklen_t sinlen = sizeof(*sin);
	int sock = accept(fd[1], (struct sockaddr *)sin, &sinlen);

	if(sock == -1) {
		fprintf(stderr, "Could not accept socket: %s\n", sockstrerror(sockerrno));
		return -1;
	}

	close(fd[1]);
	fd[1] = sock;

	int errnum;
	socklen_t len = sizeof(errnum);
	getsockopt(fd[0], SOL_SOCKET, SO_ERROR, (void *)&errnum, &len);

	if(errnum != 0) {
		fprintf(stderr, "connect error: %s\n", sockstrerror(sockerrno));
		return -1;
	}

	unset_nonblock(fd[0]);

	int option = 1;
#if defined(TCP_NODELAY)
	setsockopt(fd[0], IPPROTO_TCP, TCP_NODELAY, (void *)&option, sizeof(option));
	setsockopt(fd[1], IPPROTO_TCP, TCP_NODELAY, (void *)&option, sizeof(option));
#endif

#if defined(IP_TOS) && defined(IPTOS_LOWDELAY)
	option = IPTOS_LOWDELAY;
	setsockopt(fd[0], IPPROTO_IP, IP_TOS, (void *)&option, sizeof(option));
	setsockopt(fd[1], IPPROTO_IP, IP_TOS, (void *)&option, sizeof(option));
#endif

	return 0;
}

/* Connect fd[0] <-> fd[1], UDP */
static int connect_sockets_udp(int *fd, struct sockaddr_in *sin) {
	struct sockaddr_in sin2 = *sin;
	sin2.sin_port = htons(LOCAL_PORT + 1);

	if(bind(fd[0], (struct sockaddr *)&sin2, sizeof(sin2)) == -1) {
		fprintf(stderr, "Could not bind socket: %s\n", sockstrerror(sockerrno));
		return -1;
	}

	/* We need to explicitly connect each direction. */
	if(connect(fd[0], (struct sockaddr *)sin, sizeof(*sin)) == -1 ||
	                connect(fd[1], (struct sockaddr *)&sin2, sizeof(sin2)) == -1) {
		fprintf(stderr, "Could not connect sockets: %s\n", sockstrerror(sockerrno));
		return -1;
	}

	return 0;
}

static int socketpair(int domain, int type, int proto, int *fd) {
	int serrno;

	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr("127.0.0.1");
	sin.sin_port = htons(LOCAL_PORT);

	fd[0] = socket(AF_INET, type, proto);
	fd[1] = socket(AF_INET, type, proto);

	if(fd[0] == -1 || fd[1] == -1) {
		fprintf(stderr, "Could not create a socket: %s\n", sockstrerror(sockerrno));
		goto bad;
	}

#if defined(SOL_SOCKET) && defined(SO_REUSEPORT)
	int option = 1;
	setsockopt(fd[1], SOL_SOCKET, SO_REUSEPORT, &option, sizeof(option));
#endif

	if(bind(fd[1], (struct sockaddr *)&sin, sizeof(sin)) == -1) {
		fprintf(stderr, "Could not bind socket: %s\n", sockstrerror(sockerrno));
		goto bad;
	}

	switch(type) {
	case SOCK_STREAM:
		if(connect_sockets_tcp(fd, &sin) == -1) {
			goto bad;
		}

		break;

	case SOCK_DGRAM:
		if(connect_sockets_udp(fd, &sin) == -1) {
			goto bad;
		}

		break;

	default:
		fprintf(stderr, "Unknown socket type %d\n", type);
		goto bad;
	}

	return 0;
bad:
	serrno = errno;

	if(fd[0] != -1) {
		close(fd[0]);
	}

	if(fd[1] != -1) {
		close(fd[1]);
	}

	errno = serrno;
	return -1;
}
#endif

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

int main(int argc, char *argv[]) {
	ecdsa_t *key1, *key2;
	ecdh_t *ecdh1, *ecdh2;
	sptps_t sptps1, sptps2;
	char buf1[4096], buf2[4096], buf3[4096];
	int keytype = SPTPS_KEY_ED25519;
	int ciphertype = SPTPS_CIPHER_CHACHA20_POLY1305;
	int option_index = 0;
	int r;

	program_name = argv[0];

	while((r = getopt_long(argc, argv, "c:hk:", long_options, &option_index)) != EOF) {
		switch(r) {
		case 0: /* long option */
			break;

		case 'c': /* cipher type */
			ciphertype = sptps_parse_cipher(optarg);

			if(!ciphertype) {
				fprintf(stderr, "unsupported cipher %s.\n", optarg);
				usage();
				return 1;
			}

			break;

		case 'h': /* help */
			usage();
			return 0;

		case 'k': /* key type */
			if(strcasecmp(optarg, "ecdsa") == 0) {
				keytype = SPTPS_KEY_ECDSA;
			} else if(strcasecmp(optarg, "ed25519") == 0) {
				keytype = SPTPS_KEY_ED25519;
			} else {
				fprintf(stderr, "unsupported key type %s.\n", optarg);
				usage();
				return 1;
			}

			break;

		case '?': /* wrong options */
			usage();
			return 1;

		default:
			break;
		}
	}

	argc -= optind - 1;
	argv += optind - 1;

	double duration = argc > 1 ? atof(argv[1]) : 10;

	crypto_init();

	randomize(buf1, sizeof(buf1));
	randomize(buf2, sizeof(buf2));
	randomize(buf3, sizeof(buf3));

#ifdef HAVE_MINGW
	static struct WSAData wsa_state;

	if(WSAStartup(MAKEWORD(2, 2), &wsa_state)) {
		return 1;
	}

#endif

	// Key generation

	fprintf(stderr, "Generating keys for %lg seconds: ", duration);

	for(clock_start(); clock_countto(duration);) {
		key1 = ecdsa_generate(keytype);

		if(!key1) {
			fprintf(stderr, "unable to generate key\n");
			return 1;
		}

		ecdsa_free(key1);
	}

	fprintf(stderr, "%17.2lf op/s\n", rate);

	key1 = ecdsa_generate(keytype);
	key2 = ecdsa_generate(keytype);

	if(!key1 || !key2) {
		fprintf(stderr, "unable to generate keys\n");
		return 1;
	}

	// ECDSA signatures

	fprintf(stderr, "ECDSA sign for %lg seconds: ", duration);

	for(clock_start(); clock_countto(duration);)
		if(!ecdsa_sign(key1, buf1, 256, buf2)) {
			return 1;
		}

	fprintf(stderr, "%20.2lf op/s\n", rate);

	fprintf(stderr, "ECDSA verify for %lg seconds: ", duration);

	for(clock_start(); clock_countto(duration);)
		if(!ecdsa_verify(key1, buf1, 256, buf2)) {
			fprintf(stderr, "Signature verification failed\n");
			return 1;
		}

	fprintf(stderr, "%18.2lf op/s\n", rate);

	ecdh1 = ecdh_alloc(keytype);

	if(!ecdh1) {
		fprintf(stderr, "Could not allocate ecdh\n");
		return 1;
	}

	if(!ecdh_generate_public(ecdh1, buf1)) {
		fprintf(stderr, "Could not generate public key\n");
		return 1;
	}

	fprintf(stderr, "ECDH for %lg seconds: ", duration);

	for(clock_start(); clock_countto(duration);) {
		ecdh2 = ecdh_alloc(keytype);

		if(!ecdh2) {
			return 1;
		}

		if(!ecdh_generate_public(ecdh2, buf2)) {
			return 1;
		}

		if(!ecdh_compute_shared(ecdh2, buf1, buf3)) {
			return 1;
		}
	}

	fprintf(stderr, "%28.2lf op/s\n", rate);
	ecdh_free(ecdh1);

	// SPTPS authentication phase

	int fd[2];

	if(socketpair(AF_UNIX, SOCK_STREAM, 0, fd)) {
		fprintf(stderr, "Could not create a UNIX socket pair: %s\n", sockstrerror(sockerrno));
		return 1;
	}

	fd_set rfds;
	FD_ZERO(&rfds);
	struct timeval timo;
	int maxfd = MAX(fd[0], fd[1]);

	fprintf(stderr, "SPTPS/TCP authenticate for %lg seconds: ", duration);

	for(clock_start(); clock_countto(duration);) {
		if(!sptps_start(&sptps1, fd + 0, true, false, ciphertype, key1, key2, "sptps_speed", 11, send_data, receive_record)) {
			fprintf(stderr, "sptps_start of sptps1 failed\n");
			return 1;
		}

		if(!sptps_start(&sptps2, fd + 1, false, false, ciphertype, key2, key1, "sptps_speed", 11, send_data, receive_record)) {
			fprintf(stderr, "sptps_start of sptps2 failed\n");
			return 1;
		}

		FD_SET(fd[0], &rfds);
		FD_SET(fd[1], &rfds);
		timo.tv_sec = 0;
		timo.tv_usec = 0;

		while(select(maxfd + 1, &rfds, NULL, NULL, &timo)) {
			if(FD_ISSET(fd[0], &rfds)) {
				receive_data(&sptps1);
			}

			if(FD_ISSET(fd[1], &rfds)) {
				receive_data(&sptps2);
			}
		}

		sptps_stop(&sptps1);
		sptps_stop(&sptps2);
	}

	fprintf(stderr, "%10.2lf op/s\n", rate * 2);

	// SPTPS data

	if(!sptps_start(&sptps1, fd + 0, true, false, ciphertype, key1, key2, "sptps_speed", 11, send_data, receive_record)) {
		fprintf(stderr, "sptps_start of sptps1 failed\n");
		return 1;
	}

	if(!sptps_start(&sptps2, fd + 1, false, false, ciphertype, key2, key1, "sptps_speed", 11, send_data, receive_record)) {
		fprintf(stderr, "sptps_start of sptps2 failed\n");
		return 1;
	}

	FD_SET(fd[0], &rfds);
	FD_SET(fd[1], &rfds);
	timo.tv_sec = 0;
	timo.tv_usec = 0;

	while(select(maxfd + 1, &rfds, NULL, NULL, &timo)) {
		if(FD_ISSET(fd[0], &rfds)) {
			receive_data(&sptps1);
		}

		if(FD_ISSET(fd[1], &rfds)) {
			receive_data(&sptps2);
		}
	}

	fprintf(stderr, "SPTPS/TCP transmit for %lg seconds: ", duration);

	for(clock_start(); clock_countto(duration);) {
		if(!sptps_send_record(&sptps1, 0, buf1, 1451)) {
			abort();
		}

		receive_data(&sptps2);
	}

	rate *= 2 * 1451 * 8;

	if(rate > 1e9) {
		fprintf(stderr, "%14.2lf Gbit/s\n", rate / 1e9);
	} else if(rate > 1e6) {
		fprintf(stderr, "%14.2lf Mbit/s\n", rate / 1e6);
	} else if(rate > 1e3) {
		fprintf(stderr, "%14.2lf kbit/s\n", rate / 1e3);
	}

	sptps_stop(&sptps1);
	sptps_stop(&sptps2);

	// SPTPS datagram authentication phase

	close(fd[0]);
	close(fd[1]);

	if(socketpair(AF_UNIX, SOCK_DGRAM, 0, fd)) {
		fprintf(stderr, "Could not create a UNIX socket pair: %s\n", sockstrerror(sockerrno));
		return 1;
	}

	maxfd = MAX(fd[0], fd[1]);

	fprintf(stderr, "SPTPS/UDP authenticate for %lg seconds: ", duration);

	for(clock_start(); clock_countto(duration);) {
		if(!sptps_start(&sptps1, fd + 0, true, true, ciphertype, key1, key2, "sptps_speed", 11, send_data, receive_record)) {
			fprintf(stderr, "sptps_start of sptps1 failed\n");
			return 1;
		}

		if(!sptps_start(&sptps2, fd + 1, false, true, ciphertype, key2, key1, "sptps_speed", 11, send_data, receive_record)) {
			fprintf(stderr, "sptps_start of sptps2 failed\n");
			return 1;
		}

		FD_SET(fd[0], &rfds);
		FD_SET(fd[1], &rfds);
		timo.tv_sec = 0;
		timo.tv_usec = 0;

		while(select(maxfd + 1, &rfds, NULL, NULL, &timo)) {
			if(FD_ISSET(fd[0], &rfds)) {
				receive_data(&sptps1);
			}

			if(FD_ISSET(fd[1], &rfds)) {
				receive_data(&sptps2);
			}
		}

		sptps_stop(&sptps1);
		sptps_stop(&sptps2);
	}

	fprintf(stderr, "%10.2lf op/s\n", rate * 2);

	// SPTPS datagram data

	if(!sptps_start(&sptps1, fd + 0, true, true, ciphertype, key1, key2, "sptps_speed", 11, send_data, receive_record)) {
		fprintf(stderr, "sptps_start of sptps1 failed\n");
		return 1;
	}

	if(!sptps_start(&sptps2, fd + 1, false, true, ciphertype, key2, key1, "sptps_speed", 11, send_data, receive_record)) {
		fprintf(stderr, "sptps_start of sptps2 failed\n");
		return 1;
	}

	FD_SET(fd[0], &rfds);
	FD_SET(fd[1], &rfds);
	timo.tv_sec = 0;
	timo.tv_usec = 0;

	while(select(maxfd + 1, &rfds, NULL, NULL, &timo)) {
		if(FD_ISSET(fd[0], &rfds)) {
			receive_data(&sptps1);
		}

		if(FD_ISSET(fd[1], &rfds)) {
			receive_data(&sptps2);
		}
	}

	fprintf(stderr, "SPTPS/UDP transmit for %lg seconds: ", duration);

	for(clock_start(); clock_countto(duration);) {
		if(!sptps_send_record(&sptps1, 0, buf1, 1451)) {
			abort();
		}

		receive_data(&sptps2);
	}

	rate *= 2 * 1451 * 8;

	if(rate > 1e9) {
		fprintf(stderr, "%14.2lf Gbit/s\n", rate / 1e9);
	} else if(rate > 1e6) {
		fprintf(stderr, "%14.2lf Mbit/s\n", rate / 1e6);
	} else if(rate > 1e3) {
		fprintf(stderr, "%14.2lf kbit/s\n", rate / 1e3);
	}

	sptps_stop(&sptps1);
	sptps_stop(&sptps2);

	// Clean up

	close(fd[0]);
	close(fd[1]);
	ecdsa_free(key1);
	ecdsa_free(key2);
	crypto_exit();

	return 0;
}
