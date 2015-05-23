/*
   p0f - API query code
   --------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#ifndef _HAVE_API_H
#define _HAVE_API_H

#include "types.h"

#define P0F_MATCH_FUZZY      0x01
#define P0F_MATCH_GENERIC    0x02

#define HTTP_SERVER_INPUT_BUFFER_SIZE   4*1024      // 4kb
#define HTTP_SERVER_OUTPUT_BUFFER_SIZE  16*1024     // 16kb

struct api_client {

  s32 fd;                                    /* -1 if slot free                    */

  u8 in_data[HTTP_SERVER_INPUT_BUFFER_SIZE]; /* Query recv buffer                  */
  u32 in_off;                                /* Query buffer offset                */

  u8 out_data[HTTP_SERVER_OUTPUT_BUFFER_SIZE];    /* Response transmit buffer           */
  u32 out_length;                                 /* Resonse length */
  u32 out_off;                                    /* Response buffer offset             */

};

s32 handle_query(u8* q, u8* r);

#endif /* !_HAVE_API_H */
