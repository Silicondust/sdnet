/*
 * ./src/crypto/libtom/mpi.h
 *
 * Copyright © 2017 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#define MPI_OK MP_OKAY

struct mpi_int {
	mp_int v;
};

static inline int mpi_init(struct mpi_int *a)
{
	return mp_init(&a->v);
}

static inline void mpi_clear(struct mpi_int *a)
{
	mp_clear(&a->v);
}

static inline int mpi_exptmod(struct mpi_int *a, struct mpi_int *b, struct mpi_int *c, struct mpi_int *d)
{
	return mp_exptmod(&a->v, &b->v, &c->v, &d->v);
}

static inline size_t mpi_unsigned_bin_size(struct mpi_int *a)
{
	return (size_t)mp_unsigned_bin_size(&a->v);
}

static inline int mpi_read_unsigned_bin(struct mpi_int *a, uint8_t *b, size_t c)
{
	return mp_read_unsigned_bin(&a->v, b, (int)c);
}

static inline int mpi_to_unsigned_bin(struct mpi_int *a, uint8_t *b)
{
	return mp_to_unsigned_bin(&a->v, b);
}
