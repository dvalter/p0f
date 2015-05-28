/*
   p0f - HTTP fingerprinting
   -------------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#define _FROM_FP_HTTP
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>

#include <netinet/in.h>
#include <sys/types.h>

#include "types.h"
#include "config.h"
#include "debug.h"
#include "alloc-inl.h"
#include "process.h"
#include "p0f.h"
#include "tcp.h"
#include "hash.h"

#include "fp_http.h"

static u8** hdr_names;                 /* List of header names by ID         */
static u32  hdr_cnt;                   /* Number of headers registered       */

static u32* hdr_by_hash[SIG_BUCKETS];  /* Hashed header names                */
static u32  hbh_cnt[SIG_BUCKETS];      /* Number of headers in bucket        */

static u32 ua_map_cnt;

#define SLOF(_str) (u8*)_str, strlen((char*)_str)

/* Look up or register new header */

static s32 lookup_hdr(u8* name, u32 len, u8 create) {

  u32  bucket = hash32(name, len, hash_seed) % SIG_BUCKETS;

  u32* p = hdr_by_hash[bucket];
  u32  i = hbh_cnt[bucket];

  while (i--) {
    if (!memcmp(hdr_names[*p], name, len) && 
        !hdr_names[*p][len]) return *p;
    p++;
  }

  /* Not found! */

  if (!create) return -1;

  hdr_names = DFL_ck_realloc(hdr_names, (hdr_cnt + 1) * sizeof(u8*));
  hdr_names[hdr_cnt] = DFL_ck_memdup_str(name, len);

  hdr_by_hash[bucket] = DFL_ck_realloc(hdr_by_hash[bucket],
    (hbh_cnt[bucket] + 1) * 4);

  hdr_by_hash[bucket][hbh_cnt[bucket]++] = hdr_cnt++;

  return hdr_cnt - 1;

}


/* Pre-register essential headers. */

void http_init(void) {
  u32 i;

  /* Do not change - other code depends on the ordering of first 6 entries. */

  lookup_hdr(SLOF("User-Agent"), 1);      /* 0 */
  lookup_hdr(SLOF("Server"), 1);          /* 1 */
  lookup_hdr(SLOF("Accept-Language"), 1); /* 2 */
  lookup_hdr(SLOF("Via"), 1);             /* 3 */
  lookup_hdr(SLOF("X-Forwarded-For"), 1); /* 4 */
  lookup_hdr(SLOF("Date"), 1);            /* 5 */

#define HDR_UA  0
#define HDR_SRV 1
#define HDR_AL  2
#define HDR_VIA 3
#define HDR_XFF 4
#define HDR_DAT 5

  i = 0;
  while (req_optional[i].name) {
    req_optional[i].id = lookup_hdr(SLOF(req_optional[i].name), 1);
    i++;
  }

  i = 0;
  while (req_skipval[i].name) {
    req_skipval[i].id = lookup_hdr(SLOF(req_skipval[i].name), 1);
    i++;
  }
}

/* Dump a HTTP signature. */

static u8* dump_sig(u8 to_srv, struct http_sig* hsig) {

  u32 i;
  u8 had_prev = 0;
  struct http_id* list;

  u8 tmp[HTTP_MAX_SHOW + 1];
  u32 tpos;

  static u8* ret;
  u32 rlen = 0;

  u8* val;

#define RETF(_par...) do { \
    s32 _len = snprintf(NULL, 0, _par); \
    if (_len < 0) FATAL("Whoa, snprintf() fails?!"); \
    ret = DFL_ck_realloc_kb(ret, rlen + _len + 1); \
    snprintf((char*)ret + rlen, _len + 1, _par); \
    rlen += _len; \
  } while (0)
    
  RETF("%u:", hsig->http_ver);

  for (i = 0; i < hsig->hdr_cnt; i++) {

    if (hsig->hdr[i].id >= 0) {

      u8 optional = 0;

      /* Check the "optional" list. */

      list = req_optional;

      while (list->name) {
        if (list->id == hsig->hdr[i].id) break;
        list++;
      }

      if (list->name) optional = 1;

      RETF("%s%s%s", had_prev ? "," : "", optional ? "?" : "",
           hdr_names[hsig->hdr[i].id]);
      had_prev = 1;

      if (!(val = hsig->hdr[i].value)) continue;

      /* Next, make sure that the value is not on the ignore list. */

      if (optional) continue;

      list = req_skipval;

      while (list->name) {
        if (list->id == hsig->hdr[i].id) break;
        list++;
      }

      if (list->name) continue;

      /* Looks like it's not on the list, so let's output a cleaned-up version
         up to HTTP_MAX_SHOW. */

      tpos = 0;

      while (tpos < HTTP_MAX_SHOW && val[tpos] >= 0x20 && val[tpos] < 0x80 &&
             val[tpos] != ']' && val[tpos] != '|') {

        tmp[tpos] = val[tpos];
        tpos++;

      }

      tmp[tpos] = 0;

      if (!tpos) continue;

      RETF("=[%s]", tmp);

    } else {

      RETF("%s%s", had_prev ? "," : "", hsig->hdr[i].name);
      had_prev = 1;

      if (!(val = hsig->hdr[i].value)) continue;

      tpos = 0;

      while (tpos < HTTP_MAX_SHOW && val[tpos] >= 0x20 && val[tpos] < 0x80 &&
             val[tpos] != ']') { tmp[tpos] = val[tpos]; tpos++; }

      tmp[tpos] = 0;

      if (!tpos) continue;

      RETF("=[%s]", tmp);

    }

  }

  RETF(":");

  if ((val = hsig->sw)) {

    tpos = 0;

    while (tpos < HTTP_MAX_SHOW &&  val[tpos] >= 0x20 && val[tpos] < 0x80 &&
           val[tpos] != ']') { tmp[tpos] = val[tpos]; tpos++; }

    tmp[tpos] = 0;

    if (tpos) RETF("%s", tmp);

  }

  return ret;


}

/* Look up HTTP signature, create an observation. */

static void fingerprint_http(u8 to_srv, struct packet_flow* f) {
  u8* p;
  u8* http_signature;
  struct host_data* client;


  http_signature = dump_sig(to_srv, &f->http_tmp);

  start_observation(to_srv ? "http request" : "http response", 1, to_srv, f);
  add_observation_field("http_signature", http_signature);

  if(!f->orig_cli_port) {
    client = f->client;
    client->http_req_port = f->cli_port;

  } else {
    client = lookup_host(f->orig_cli_addr, IP_VER4);

    if(!client) {
      DEBUG("[#] Could not find real client: %s:%u\n", addr_to_str(f->orig_cli_addr, IP_VER4), f->orig_cli_port);
      client = f->client;
    } else {
      DEBUG("[#] Attributing http findings to real client: %s:%u\n", addr_to_str(f->orig_cli_addr, IP_VER4), f->orig_cli_port);
    }

    client->http_req_port = f->orig_cli_port;
  }

  p = strncpy(
    (char*)client->http_signature,
    http_signature,
    strlen(http_signature) > SIGNATURE_LENGTH ? SIGNATURE_LENGTH : strlen(http_signature)
  );
  p = "\0";
}



/* Free up any allocated strings in http_sig. */

void free_sig_hdrs(struct http_sig* h) {

  u32 i;

  for (i = 0; i < h->hdr_cnt; i++) {
    if (h->hdr[i].name) ck_free(h->hdr[i].name);
    if (h->hdr[i].value) ck_free(h->hdr[i].value);
  }

}

/* Parse name=value pairs into a signature. */

static u8 parse_pairs(u8 to_srv, struct packet_flow* f, u8 can_get_more) {

  u32 plen = to_srv ? f->req_len : f->resp_len;

  u32 off;

  /* Try to parse name: value pairs. */

  while ((off = f->http_pos) < plen) {

    u8* pay = to_srv ? f->request : f->response;

    u32 nlen, vlen, vstart;
    s32 hid;
    u32 hcount;

    /* Empty line? Dispatch for fingerprinting! */

    if (pay[off] == '\r' || pay[off] == '\n') {

      f->http_tmp.recv_date = get_unix_time();

      fingerprint_http(to_srv, f);

      /* If this is a request, flush the collected signature and prepare
         for parsing the response. If it's a response, just shut down HTTP
         parsing on this flow. */

      if (to_srv) {

        f->http_req_done = 1;
        f->http_pos = 0;

        free_sig_hdrs(&f->http_tmp);
        memset(&f->http_tmp, 0, sizeof(struct http_sig));

        return 1;

      } else {

        f->in_http = -1;
        return 0;

      }

    }

    /* Looks like we're getting a header value. See if we have room for it. */

    if ((hcount = f->http_tmp.hdr_cnt) >= HTTP_MAX_HDRS) {

      DEBUG("[#] Too many HTTP headers in a %s.\n", to_srv ? "request" :
            "response");

      f->in_http = -1;
      return 0;

    }

    /* Try to extract header name. */
      
    nlen = 0;

    while ((isalnum(pay[off]) || pay[off] == '-' || pay[off] == '_') &&
           off < plen && nlen <= HTTP_MAX_HDR_NAME) {

      off++;
      nlen++;

    }

    if (off == plen) {

      if (!can_get_more) {

        DEBUG("[#] End of HTTP %s before end of headers.\n",
              to_srv ? "request" : "response");
        f->in_http = -1;

      }

      return can_get_more;

    }

    /* Empty, excessively long, or non-':'-followed header name? */

    if (!nlen || pay[off] != ':' || nlen > HTTP_MAX_HDR_NAME) {

      DEBUG("[#] Invalid HTTP header encountered (len = %u, char = 0x%02x).\n",
            nlen, pay[off]);

      f->in_http = -1;
      return 0;

    }

    /* At this point, header name starts at f->http_pos, and has nlen bytes.
       Skip ':' and a subsequent whitespace next. */

    off++;

    if (off < plen && isblank(pay[off])) off++;

    vstart = off;
    vlen = 0;

    /* Find the next \n. */

    while (off < plen && vlen <= HTTP_MAX_HDR_VAL && pay[off] != '\n') {

      off++;
      vlen++;

    }

    if (vlen > HTTP_MAX_HDR_VAL) {
      DEBUG("[#] HTTP %s header value length exceeded.\n",
            to_srv ? "request" : "response");
      f->in_http = -1;
      return -1;
    }

    if (off == plen) {

      if (!can_get_more) {
        DEBUG("[#] End of HTTP %s before end of headers.\n",
              to_srv ? "request" : "response");
        f->in_http = -1;
      }

      return can_get_more;

    }

    /* If party is using \r\n terminators, go back one char. */

    if (pay[off - 1] == '\r') vlen--;
 
    /* Header value starts at vstart, and has vlen bytes (may be zero). Record
       this in the signature. */

    hid = lookup_hdr(pay + f->http_pos, nlen, 0);

    f->http_tmp.hdr[hcount].id = hid;

    if (hid < 0) {

      /* Header ID not found, store literal value. */

      f->http_tmp.hdr[hcount].name = ck_memdup_str(pay + f->http_pos, nlen);

    }

    /* If there's a value, store that too. For U-A and Server, also update
       'sw'; and for requests, collect Accept-Language. */

    if (vlen) {

      u8* val = ck_memdup_str(pay + vstart, vlen);

      f->http_tmp.hdr[hcount].value = val;

      if (hid == HDR_UA) f->http_tmp.sw = val;
    }

    /* Moving on... */

    f->http_tmp.hdr_cnt++;
    f->http_pos = off + 1; 

  }

  if (!can_get_more) {
    DEBUG("[#] End of HTTP %s before end of headers.\n",
          to_srv ? "request" : "response");
    f->in_http = -1;
  }

  return can_get_more;

}


/* Examine request or response; returns 1 if more data needed and plausibly can
   be read. Note that the buffer is always NUL-terminated. */

u8 process_http(u8 to_srv, struct packet_flow* f) {
  //no tracking for server responses
  if (!to_srv) return 0;

  /* Already decided this flow is not worth tracking? */

  if (f->in_http < 0) return 0;

  u8* pay = f->request;
  u8 can_get_more = (f->req_len < MAX_FLOW_DATA);
  u32 off;
  u32 off_proxyprotocol = 0;
  u8 i;
  u8 tmp[50];

  /* Request done, but pending response? */

  if (f->http_req_done) return 1;

  if (!f->in_http) {

    u8 chr;
    u8* sig_at;

    /* Ooh, new flow! */

    if (f->req_len < 15) return can_get_more;

    /* Scan until \n, or until binary data spotted. */

    off = f->http_pos;

    /* We only care about GET and HEAD requests at this point. */

    if(!strncmp((char*)pay, "PROXY ", 6)) {
      pay = pay + 6;
      off_proxyprotocol = 6;

      if(!strncmp((char*)pay, "TCP4 ", 5)) {
        if (f->req_len < 56 /* max proxy header length for ipv4 */ + 15 /* min http header length */) return can_get_more;

        pay = pay + 5;
        off_proxyprotocol = off_proxyprotocol + 5;

        //parse source ip address
        memset(&tmp, 0, sizeof(tmp));
        i=0; while(i < sizeof(tmp) && (chr = pay[i]) != ' ') { tmp[i] = pay[i]; i++; }
        pay = pay + i + 1;
        off_proxyprotocol = off_proxyprotocol + i + 1;
        if (inet_pton(AF_INET, tmp, f->orig_cli_addr) <= 0) {
          DEBUG("Could not parse destination address\n");
          return 0;
        }

        //parse destination ip address
        memset(&tmp, 0, sizeof(tmp));
        i=0; while(i < sizeof(tmp) && (chr = pay[i]) != ' ') { tmp[i] = pay[i]; i++; }
        pay = pay + i + 1;
        off_proxyprotocol = off_proxyprotocol + i + 1;

        //parse source port
        memset(&tmp, 0, sizeof(tmp));
        i=0; while(i < sizeof(tmp) && (chr = pay[i]) != ' ') { tmp[i] = pay[i]; i++; }
        pay = pay + i + 1;
        off_proxyprotocol = off_proxyprotocol + i + 1;
        f->orig_cli_port = atoi(tmp);

        //parse destination port
        memset(&tmp, 0, sizeof(tmp));
        i=0; while(i < sizeof(tmp) && (chr = pay[i]) != '\r') { tmp[i] = pay[i]; i++; }
        pay = pay + i + 1;
        off_proxyprotocol = off_proxyprotocol + i + 1;

        DEBUG("[#] Found encapsulating proxy protocol v1 TCP4 originating from %s:%u\n", addr_to_str(f->orig_cli_addr, IP_VER4), f->orig_cli_port);

        //skip \n
        pay = pay + 1;
        off_proxyprotocol = off_proxyprotocol + 1;

      } else if(!strncmp((char*)pay, "TCP6 ", 5)) {
        DEBUG("[#] Found proxy protocol v1 TCP6 which is not unsupported\n");
        return 0;

      } else {
        DEBUG("[#] Missing TCP4, TCP6 specification for proxy protocol.\n");
        return 0;
      }
    }

    if (!off && strncmp((char*)pay, "GET /", 5) &&
        strncmp((char*)pay, "HEAD /", 6)) {
      DEBUG("[#] Does not seem like a GET / HEAD request.\n");
      f->in_http = -1;
      return 0;
    }

    while (off < f->req_len && off < HTTP_MAX_URL &&
           (chr = pay[off]) != '\n') {

      if (chr != '\r' && (chr < 0x20 || chr > 0x7f)) {

        DEBUG("[#] Not HTTP - character 0x%02x encountered.\n", chr);

        f->in_http = -1;
        return 0;
      }

      off++;

    }

    /* Newline too far or too close? */

    if (off == HTTP_MAX_URL || off < 14) {

      DEBUG("[#] Not HTTP - newline offset %u.\n", off);

      f->in_http = -1;
      return 0;

    }

    /* Not enough data yet? */

    if (off == f->req_len) {

      f->http_pos = off;

      if (!can_get_more) {

        DEBUG("[#] Not HTTP - no opening line found.\n");
        f->in_http = -1;

      }

      return can_get_more;

    }

    sig_at = pay + off - 8;
    if (pay[off - 1] == '\r') sig_at--;

    /* Bad HTTP/1.x signature? */

    if (strncmp((char*)sig_at, "HTTP/1.", 7)) {

      DEBUG("[#] Not HTTP - bad signature.\n");

      f->in_http = -1;
      return 0;

    }

    f->http_tmp.http_ver = (sig_at[7] == '1');

    f->in_http  = 1;
    f->http_pos = off + 1;

    DEBUG("[#] HTTP detected.\n");

  }

  f->http_pos = f->http_pos + off_proxyprotocol;

  return parse_pairs(1, f, can_get_more);

}
