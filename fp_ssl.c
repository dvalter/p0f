/* -*-mode:c; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
  p0f - SSL fingerprinting
  -------------------------

  Copyright (C) 2012 by Marek Majkowski <marek@popcount.org>

  Distributed under the terms and conditions of GNU LGPL.

*/

#define _FROM_FP_SSL
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

#include "fp_ssl.h"

/* Flags for SSL signaturs */
struct flag {
  char* name;
  int name_len;
  u32 value;
};

struct flag flags[] = {{"compr", 5, SSL_FLAG_COMPR},
                       {"v2",    2, SSL_FLAG_V2},
                       {"ver",   3, SSL_FLAG_VER},
                       {"rtime", 5, SSL_FLAG_RTIME},
                       {"stime", 5, SSL_FLAG_STIME},
                       {NULL, 0, 0}};


/* Signatures are stored as flat list. Matching is fast: ssl version
   and flags must match exactly, matching ciphers and extensions
   usually require looking only at a first few bytes of the
   signature. Assuming the signature doesn't start with a star. */

static struct ssl_sig_record* signatures;
static u32 signatures_cnt;


/* Decode a string of comma separated hex numbers into an annotated
   u32 array. Exit with success on '\0' or ':'. */

static u32* decode_hex_string(const u8** val_ptr, u32 line_no) {

  const u8* val = *val_ptr;

  u32 rec[SSL_MAX_CIPHERS];
  u8 p = 0;

  while (p < SSL_MAX_CIPHERS) {

    u32 optional = 0;
    const u8* prev_val;
    u32* ret;

    /* State #1: expecting value */

    switch (*val) {

    case '*':
      rec[p++] = MATCH_ANY;
      val ++;
      break;

    case '?':
      optional = MATCH_MAYBE;
      val ++;
      /* Must be a hex digit after question mark */
    case 'a' ... 'f':
    case '0' ... '9':
      prev_val = val;
      rec[p++] = (strtol((char*)val, (char**)&val, 16) & 0xFFFFFF) | optional;
      if (val == prev_val) return NULL;
      break;

    default:
      /* Support empty list - jump to second state. */
      if (p == 0)
        break;

      return NULL;

    }

    /* State #2: comma, expecting '\0' or ':' */

    switch (*val) {

    case ':':
    case '\0':
      *val_ptr = val;
      ret = DFL_ck_alloc((p + 1) * sizeof(u32));
      memcpy(ret, rec, p * sizeof(u32));
      ret[p] = END_MARKER;
      return ret;

    case ',':
      val ++;
      break;

    default:
      return NULL;

    }

  }

  FATAL("Too many ciphers or extensions in line %u.", line_no);

}


/* Is u32 list of ciphers/extensions matching the signature?
   first argument is record (star and question mark allowed),
   second one is an exact signature. */

/* Unpack SSLv3 fragment to a signature. We expect to hear ClientHello
 message.  -1 on parsing error, 1 if signature was extracted. */

static int fingerprint_ssl_v3(struct ssl_sig* sig, const u8* fragment,
                              u32 frag_len, u16 record_version, u32 local_time) {

  int i;
  const u8* frag_end = fragment + frag_len;

  struct ssl3_message_hdr* msg = (struct ssl3_message_hdr*)fragment;
  u32 msg_len = (msg->length[0] << 16) |
                (msg->length[1] << 8) |
                (msg->length[2]);

  const u8* pay = (const u8*)msg + sizeof(struct ssl3_message_hdr);
  const u8* pay_end = pay + msg_len;
  const u8* tmp_end;


  /* Record size goes beyond current fragment, it's fine by SSL but
     not for us. */

  if (pay_end > frag_end) {

    DEBUG("[#] SSL Fragment coalescing not supported - %u bytes requested.\n",
          pay_end - frag_end);

    return -1;

  }

  if (msg->message_type != SSL3_MSG_CLIENT_HELLO) {

    /* Rfc526 says: The handshake protocol messages are presented
         below in the order they MUST be sent; sending handshake
         messages in an unexpected order results in a fatal error.

       I guess we can assume that the first frame must be ClientHello.
    */

    DEBUG("[#] SSL First message type 0x%02x (%u bytes) not supported.\n",
          msg->message_type, msg_len);
    return -1;

  }


  /* ClientHello */


  /* Header (34B) + session_id_len (1B) */

  if (pay + 2 + 4 + 28 + 1 > pay_end) goto too_short;

  sig->request_version = (pay[0] << 8) | pay[1];
  pay += 2;

  if (sig->request_version != record_version) {
    sig->flags |= SSL_FLAG_VER;
  }

  sig->remote_time = ntohl(*((u32*)pay));
  pay += 4;

  sig->recv_time = local_time;
  s64 drift = ((s64)sig->recv_time) - sig->remote_time;

  if (sig->remote_time < 1*365*24*60*60) {

    /* Old Firefox on windows uses time since boot */
    sig->flags |= SSL_FLAG_STIME;

  } else if (abs(drift) > 5*365*24*60*60) {

    /* More than 5 years difference - most likely random */
    sig->flags |= SSL_FLAG_RTIME;

    DEBUG("[#] SSL timer looks wrong: drift=%lld remote_time=%u.\n",
          drift, sig->remote_time);

  }

  /* Random */
  u16* random = (u16*)pay;
  pay += 28;

  for (i = 0; i < 14; i++) {
    if (random[i] == 0x0000 || random[i] == 0xffff) {

      DEBUG("[#] SSL 0x%04x found in allegedly random blob at offset %i.\n",
            random[i], i);
      break;

    }
  }

  /* Skip session_id */
  u8 session_id_len = pay[0];
  pay += 1;

  if (pay + session_id_len + 2 > pay_end) goto too_short;

  pay += session_id_len;


  /* Cipher suites */

  u16 cipher_suites_len = (pay[0] << 8) | pay[1];
  pay += 2;

  if (cipher_suites_len % 2) {

    DEBUG("[#] SSL cipher_suites_len=%u is not even.\n", cipher_suites_len);
    return -1;

  }

  if (pay + cipher_suites_len > pay_end) goto too_short;

  int cipher_pos = 0;
  sig->cipher_suites = ck_alloc(((cipher_suites_len / 2) + 1) * sizeof(u32));
  tmp_end = pay + cipher_suites_len;

  while (pay < tmp_end) {

    sig->cipher_suites[cipher_pos++] = (pay[0] << 8) | pay[1];
    pay += 2;

  }
  sig->cipher_suites[cipher_pos] = END_MARKER;

  if (pay + 1 > pay_end) goto truncated;

  u8 compression_methods_len = pay[0];
  pay += 1;

  if (pay + compression_methods_len > pay_end) goto truncated;

  tmp_end = pay + compression_methods_len;

  while (pay < tmp_end) {

    if (pay[0] == 1) {
      sig->flags |= SSL_FLAG_COMPR;
    }

    pay += 1;

  }


  if (pay + 2 > pay_end) {

    /* Extensions are optional in SSLv3. This behaviour was considered
       as a flag, but it doesn't bring any entropy. In other words:
       noone who is able to send extensions sends an empty list.  An
       empty list of extensions is equal to SSLv2 or this branch. */
    goto truncated_ok;

  }

  u16 extensions_len = (pay[0] << 8) | pay[1];
  pay += 2;

  if (pay + extensions_len > pay_end) goto truncated;

  int extensions_pos = 0;
  sig->extensions = ck_alloc(((extensions_len / 4) + 1) * sizeof(u32));
  tmp_end = pay + extensions_len;

  while (pay + 4 <= tmp_end) {

    u16 ext_type = (pay[0] << 8) | pay[1];
    u16 ext_len  = (pay[2] << 8) | pay[3];
    const u8* extension = &pay[4];
    pay += 4;

    pay += ext_len;

    sig->extensions[extensions_pos++] = ext_type;

    /* Extension payload sane? */
    if (pay > tmp_end) break;

    /* Ignore the actual value of the extenstion. */
    extension = extension;
  }

  /* Make sure the terminator is always appended, even if extensions
     are malformed. */
  sig->extensions = ck_realloc(sig->extensions, (extensions_pos + 1) *
                               sizeof(u32));
  sig->extensions[extensions_pos] = END_MARKER;

  if (pay != tmp_end) {

    DEBUG("[#] SSL malformed extensions, %i bytes over.\n",
          pay - tmp_end);

  }

  if (pay != pay_end) {

    DEBUG("[#] SSL ClientHello remaining %i bytes after extensions.\n",
          pay_end - pay);

  }

  if (pay_end != frag_end) {

    DEBUG("[#] SSL %i bytes remaining after ClientHello message.\n",
          frag_end - pay_end);

  }

  if (0) {
truncated:

    DEBUG("[#] SSL packet truncated (but valid).\n");

  }
truncated_ok:

  if (!sig->extensions) {
    sig->extensions    = ck_alloc(1*sizeof(u32));
    sig->extensions[0] = END_MARKER;
  }

  return 1;


too_short:

  DEBUG("[#] SSL packet truncated.\n");

  ck_free(sig->cipher_suites);
  ck_free(sig->extensions);

  return -1;

}


/* Signature - to - string */

static u8* dump_sig(struct ssl_sig* sig, u8 fingerprint) {

  int i;

  static u8* ret;
  u32 rlen = 0;

#define RETF(_par...) do {                           \
    s32 _len = snprintf(NULL, 0, _par);              \
    if (_len < 0) FATAL("Whoa, snprintf() fails?!"); \
    ret = DFL_ck_realloc_kb(ret, rlen + _len + 1);   \
    snprintf((char*)ret + rlen, _len + 1, _par);     \
    rlen += _len;                                    \
  } while (0)

  RETF("%i.%i|", sig->request_version >> 8, sig->request_version & 0xFF);

  for (i = 0; sig->cipher_suites[i] != END_MARKER; i++) {
    u32 c = sig->cipher_suites[i];
    if (c != MATCH_ANY) {
      RETF("%s%s%x", (i ? "," : ""),
           (c & MATCH_MAYBE) ? "?" : "",
           c & ~MATCH_MAYBE);
    } else {
      RETF("%s*", (i ? "," : ""));
    }
  }

  RETF("|");

  for (i = 0; sig->extensions[i] != END_MARKER; i++) {
    u32 ext = sig->extensions[i];
    if (ext != MATCH_ANY) {
      u8 optional = 0;
      if (fingerprint && ext == 0) {
        optional = 1;
      }
      RETF("%s%s%x", (i ? "," : ""),
           ((ext & MATCH_MAYBE) || optional) ? "?" : "",
           ext & ~MATCH_MAYBE);
    } else {
      RETF("%s*", (i ? "," : ""));
    }
  }

  RETF("|");

  int had_prev = 0;
  for (i = 0; flags[i].name != NULL; i++) {

    if (sig->flags & flags[i].value) {
      RETF("%s%s", (had_prev ? "," : ""), flags[i].name);
      had_prev = 1;
    }

  }

  return ret;

}

/* Given an SSL client signature look it up and create an observation.  */

static void fingerprint_ssl(u8 to_srv, struct packet_flow* f,
                            struct ssl_sig* sig) {

  /* Client request only. */
  if (to_srv != 1) return;

  start_observation("ssl request", 3, to_srv, f);

  if ((sig->flags & (SSL_FLAG_RTIME | SSL_FLAG_STIME)) == 0) {

    s64 drift = ((s64)sig->recv_time) - sig->remote_time;
    OBSERVF("drift", "%lld", drift);

  } else {

    add_observation_field("drift", NULL);

  }

  OBSERVF("remote_time", "%u", sig->remote_time);

  add_observation_field("raw_sig", dump_sig(sig, 1));
}


/* Examine request or response; returns 1 if more data needed and
   plausibly can be read. Note that the buffer is always NULL
   terminated. */

u8 process_ssl(u8 to_srv, struct packet_flow* f) {

  int success = 0;
  struct ssl_sig sig;
  u8 *raw_sig;
  u8 *p;

  /* Already decided this flow? */

  if (f->in_ssl) return 0;


  /* Tracking requests only. */

  if (!to_srv) return 0;


  u8 can_get_more = (f->req_len < MAX_FLOW_DATA);


  /* SSLv3 record is 5 bytes, message is 4 + 38; SSLv2 CLIENT-HELLO is
     11 bytes - we try to recognize protocol by looking at top 6
     bytes. */

  if (f->req_len < 6) return can_get_more;

  struct ssl3_record_hdr* hdr3 = (struct ssl3_record_hdr*)f->request;
  u16 fragment_len = ntohs(hdr3->length);

  /* Top 5 bytes of SSLv3/TLS header? Currently available TLS
     versions: 3.0 - 3.3. The rfc disallows fragment to have more than
     2^14 bytes. Also length less than 4 bytes doesn't make much
     sense. Additionally let's peek the meesage type. */

   if (hdr3->content_type == SSL3_REC_HANDSHAKE &&
           hdr3->ver_maj == 3 && hdr3->ver_min < 4 &&
           fragment_len > 3 && fragment_len < (1 << 14) &&
           f->request[5] == SSL3_MSG_CLIENT_HELLO) {

    if (f->req_len < sizeof(struct ssl3_record_hdr) + fragment_len)
      return can_get_more;

    memset(&sig, 0, sizeof(struct ssl_sig));
    u16 record_version = (hdr3->ver_maj << 8) | hdr3->ver_min;

    u8* fragment = f->request + sizeof(struct ssl3_record_hdr);

    success = fingerprint_ssl_v3(&sig, fragment, fragment_len,
                                 record_version,
                                 f->client->last_seen);

  }

  if (success != 1) {

    DEBUG("[#] Does not look like SSLv3.\n");

    f->in_ssl = -1;
    return 0;

  }


  f->in_ssl = 1;

  fingerprint_ssl(to_srv, f, &sig);

  raw_sig = dump_sig(&sig, 0);
  p = strncpy(
    (char*)f->client->ssl_signature,
    raw_sig,
    strlen(raw_sig) > SIGNATURE_LENGTH ? SIGNATURE_LENGTH : strlen(raw_sig)
  );
  p = "\0";


  if (sig.remote_time && !(sig.flags & SSL_FLAG_RTIME)) {
    f->client->ssl_remote_time         = sig.remote_time;
    f->client->ssl_remote_time_drift   = sig.remote_time - sig.recv_time;
  }


  ck_free(sig.cipher_suites);
  ck_free(sig.extensions);

  return 0;

}
