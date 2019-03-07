/*
 * BPFHV paravirtual network device
 *   Definitions shared between the device emulation and the
 *   proxy net backend.
 *
 * Copyright (c) 2019 Vincenzo Maffione <v.maffione@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __BPFHV_NETPROXY_H__
#define __BPFHV_NETPROXY_H__

#include "net/net.h"

struct BpfhvProxyState;

struct BpfhvProxyState *bpfhv_proxy_get(NetClientState *nc);

int bpfhv_proxy_get_features(struct BpfhvProxyState *s, uint64_t *features);
int bpfhv_proxy_set_features(struct BpfhvProxyState *s, uint64_t features);
int bpfhv_proxy_set_parameters(struct BpfhvProxyState *s,
                               unsigned int num_rx_bufs,
                               unsigned int num_tx_bufs);
#endif  /* __BPFHV_NETPROXY_H__ */
