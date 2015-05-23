/*
   p0f - MTU matching
   ------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <netinet/in.h>
#include <sys/types.h>
#include <ctype.h>

#include "types.h"
#include "config.h"
#include "debug.h"
#include "alloc-inl.h"
#include "process.h"
#include "readfp.h"
#include "p0f.h"
#include "tcp.h"

#include "fp_mtu.h"

void fingerprint_mtu(u8 to_srv, struct packet_data* pk, struct packet_flow* f) {
  u16 mtu;

  start_observation("mtu", 2, to_srv, f);

  if (!pk->mss || f->sendsyn) return;

  if (pk->ip_ver == IP_VER4) mtu = pk->mss + MIN_TCP4;
  else mtu = pk->mss + MIN_TCP6;

  if (to_srv) f->client->mtu = mtu;
  else f->server->mtu = mtu;

  add_observation_field("link", NULL);
  OBSERVF("raw_mtu", "%u", mtu);
}
