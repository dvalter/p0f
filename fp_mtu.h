/*
   p0f - MTU matching
   ------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#ifndef _HAVE_FP_MTU_H
#define _HAVE_FP_MTU_H

#include "types.h"

#include "process.h"

struct packet_data;
struct packet_flow;

void fingerprint_mtu(u8 to_srv, struct packet_data* pk, struct packet_flow* f);

#endif /* _HAVE_FP_MTU_H */
