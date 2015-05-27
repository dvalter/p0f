/*
   p0f - HTTP fingerprinting
   -------------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#ifndef _HAVE_FP_HTTP_H
#define _HAVE_FP_HTTP_H

#include "types.h"

/* A structure used for looking up various headers internally in fp_http.c: */

struct http_id {
  char* name;
  u32 id;
};

/* HTTP header field: */

struct http_hdr {
  s32  id;                              /* Lookup ID (-1 = none)              */
  u8*  name;                            /* Text name (NULL = use lookup ID)   */
  u8*  value;                           /* Value, if any                      */
  u8   optional;                        /* Optional header?                   */
};

/* Request / response signature collected from the wire: */

struct http_sig {

  s8  http_ver;                         /* HTTP version (-1 = any)            */

  struct http_hdr hdr[HTTP_MAX_HDRS];   /* Mandatory / discovered headers     */
  u32 hdr_cnt;

  u8* sw;                               /* Software string (U-A or Server)    */

  u32 recv_date;                        /* Actual receipt date                */
};

struct packet_flow;

u8 process_http(u8 to_srv, struct packet_flow* f);

void free_sig_hdrs(struct http_sig* h);

void http_init(void);

#endif /* _HAVE_FP_HTTP_H */
