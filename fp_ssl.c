/* -*-mode:c; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
  p0f - SSL fingerprinting
  -------------------------

  Copyright (C) 2012 by Marek Majkowski <marek@popcount.org>

  Copyright (C) 2022 by Dmitry Valter <dvalter@protonmail.com>

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


/*
 * tls-hello-dump.c
 *
 * TLS ClientHello/ServerHello Dumper (for XMPP).
 *
 * Version 0.5 (2013-11-06)
 * Copyright (C) 2013 Georg Lukas <georg@op-co.de>
 *
 ****************************************************************************
 *
 * This software is a modification of:
 *
 * sniffex.c
 *
 * Sniffer example of TCP/IP packet capture using libpcap.
 * 
 * Version 0.1.1 (2005-07-05)
 * Copyright (c) 2005 The Tcpdump Group
 *
 * This software is intended to be used as a practical example and 
 * demonstration of the libpcap library; available at:
 * http://www.tcpdump.org/
 *
 ****************************************************************************
 *
 * This software is a modification of Tim Carstens' "sniffer.c"
 * demonstration source code, released as follows:
 * 
 * sniffer.c
 * Copyright (c) 2002 Tim Carstens
 * 2002-01-07
 * Demonstration of using libpcap
 * timcarst -at- yahoo -dot- com
 * 
 * "sniffer.c" is distributed under these terms:
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. The name "Tim Carstens" may not be used to endorse or promote
 *    products derived from this software without prior written permission
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * <end of "sniffer.c" terms>
 *
 * This software, "sniffex.c", is a derivative work of "sniffer.c" and is
 * covered by the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Because this is a derivative work, you must comply with the "sniffer.c"
 *    terms reproduced above.
 * 2. Redistributions of source code must retain the Tcpdump Group copyright
 *    notice at the top of this source file, this list of conditions and the
 *    following disclaimer.
 * 3. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. The names "tcpdump" or "libpcap" may not be used to endorse or promote
 *    products derived from this software without prior written permission.
 *
 * THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM.
 * BECAUSE THE PROGRAM IS LICENSED FREE OF CHARGE, THERE IS NO WARRANTY
 * FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW.  EXCEPT WHEN
 * OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES
 * PROVIDE THE PROGRAM "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED
 * OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.  THE ENTIRE RISK AS
 * TO THE QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH YOU.  SHOULD THE
 * PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING,
 * REPAIR OR CORRECTION.
 * 
 * IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING
 * WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY MODIFY AND/OR
 * REDISTRIBUTE THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES,
 * INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING
 * OUT OF THE USE OR INABILITY TO USE THE PROGRAM (INCLUDING BUT NOT LIMITED
 * TO LOSS OF DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY
 * YOU OR THIRD PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE WITH ANY OTHER
 * PROGRAMS), EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES.
 * <end of "sniffex.c" terms>
 * 
 ****************************************************************************
 *
 * Below is an excerpt from an email from Guy Harris on the tcpdump-workers
 * mail list when someone asked, "How do I get the length of the TCP
 * payload?" Guy Harris' slightly snipped response (edited by him to
 * speak of the IPv4 header length and TCP data offset without referring
 * to bitfield structure members) is reproduced below:
 * 
 * The Ethernet size is always 14 bytes.
 * 
 * <snip>...</snip>
 *
 * In fact, you *MUST* assume the Ethernet header is 14 bytes, *and*, if 
 * you're using structures, you must use structures where the members 
 * always have the same size on all platforms, because the sizes of the 
 * fields in Ethernet - and IP, and TCP, and... - headers are defined by 
 * the protocol specification, not by the way a particular platform's C 
 * compiler works.)
 *
 * The IP header size, in bytes, is the value of the IP header length,
 * as extracted from the "ip_vhl" field of "struct sniff_ip" with
 * the "IP_HL()" macro, times 4 ("times 4" because it's in units of
 * 4-byte words).  If that value is less than 20 - i.e., if the value
 * extracted with "IP_HL()" is less than 5 - you have a malformed
 * IP datagram.
 *
 * The TCP header size, in bytes, is the value of the TCP data offset,
 * as extracted from the "th_offx2" field of "struct sniff_tcp" with
 * the "TH_OFF()" macro, times 4 (for the same reason - 4-byte words).
 * If that value is less than 20 - i.e., if the value extracted with
 * "TH_OFF()" is less than 5 - you have a malformed TCP segment.
 *
 * So, to find the IP header in an Ethernet packet, look 14 bytes after 
 * the beginning of the packet data.  To find the TCP header, look 
 * "IP_HL(ip)*4" bytes after the beginning of the IP header.  To find the
 * TCP payload, look "TH_OFF(tcp)*4" bytes after the beginning of the TCP
 * header.
 * 
 * To find out how much payload there is:
 *
 * Take the IP *total* length field - "ip_len" in "struct sniff_ip" 
 * - and, first, check whether it's less than "IP_HL(ip)*4" (after
 * you've checked whether "IP_HL(ip)" is >= 5).  If it is, you have
 * a malformed IP datagram.
 *
 * Otherwise, subtract "IP_HL(ip)*4" from it; that gives you the length
 * of the TCP segment, including the TCP header.  If that's less than
 * "TH_OFF(tcp)*4" (after you've checked whether "TH_OFF(tcp)" is >= 5),
 * you have a malformed TCP segment.
 *
 * Otherwise, subtract "TH_OFF(tcp)*4" from it; that gives you the
 * length of the TCP payload.
 *
 * Note that you also need to make sure that you don't go past the end 
 * of the captured data in the packet - you might, for example, have a 
 * 15-byte Ethernet packet that claims to contain an IP datagram, but if 
 * it's 15 bytes, it has only one byte of Ethernet payload, which is too 
 * small for an IP header.  The length of the captured data is given in 
 * the "caplen" field in the "struct pcap_pkthdr"; it might be less than 
 * the length of the packet, if you're capturing with a snapshot length 
 * other than a value >= the maximum packet size.
 * <end of response>
 * 
 ****************************************************************************
 * 
 * Example compiler command-line for GCC:
 *   gcc -Wall -o sniffex sniffex.c -lpcap
 * 
 ****************************************************************************
 *
 * Code Comments
 *
 * This section contains additional information and explanations regarding
 * comments in the source code. It serves as documentaion and rationale
 * for why the code is written as it is without hindering readability, as it
 * might if it were placed along with the actual code inline. References in
 * the code appear as footnote notation (e.g. [1]).
 *
 * 1. Ethernet headers are always exactly 14 bytes, so we define this
 * explicitly with "#define". Since some compilers might pad structures to a
 * multiple of 4 bytes - some versions of GCC for ARM may do this -
 * "sizeof (struct sniff_ethernet)" isn't used.
 * 
 * 2. Check the link-layer type of the device that's being opened to make
 * sure it's Ethernet, since that's all we handle in this example. Other
 * link-layer types may have different length headers (see [1]).
 *
 * 3. This is the filter expression that tells libpcap which packets we're
 * interested in (i.e. which packets to capture). Since this source example
 * focuses on IP and TCP, we use the expression "ip", so we know we'll only
 * encounter IP packets. The capture filter syntax, along with some
 * examples, is documented in the tcpdump man page under "expression."
 * Below are a few simple examples:
 *
 * Expression     Description
 * ----------     -----------
 * ip         Capture all IP packets.
 * tcp          Capture only TCP packets.
 * tcp port 80      Capture only TCP packets with a port equal to 80.
 * ip host 10.1.2.3   Capture all IP packets to or from host 10.1.2.3.
 *
 ****************************************************************************
 *
 */

#include <pwd.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#define SSL_MIN_GOOD_VERSION  0x002
#define SSL_MAX_GOOD_VERSION  0x304 // let's be optimistic here!

#define TLS_HANDSHAKE   22
#define TLS_CLIENT_HELLO  1
#define TLS_SERVER_HELLO  2

#define OFFSET_HELLO_VERSION  9
#define OFFSET_SESSION_LENGTH 43
#define OFFSET_CIPHER_LIST  44

// for fingerprint
#define TLS_EXT_MAX 64

char*
ssl_version(u_short version) {
  static char hex[7];
  switch (version) {
    case 0x002: return "SSLv2";
    case 0x300: return "SSLv3";
    case 0x301: return "TLSv1";
    case 0x302: return "TLSv1.1";
    case 0x303: return "TLSv1.2";
  }
  snprintf(hex, sizeof(hex), "0x%04hx", version);
  return hex;
}

/* Is u32 list of ciphers/extensions matching the signature?
   first argument is record (star and question mark allowed),
   second one is an exact signature. */

/* Unpack TLS fragment to a signature. We expect to hear ClientHello
 message.  -1 on parsing error, 1 if signature was extracted. */

static int fingerprint_tls(struct ssl_sig* sig, const u8* payload,
                              u32 frag_len, u16 record_version, u32 local_time) {
  int size_ip;
  int size_iptotal;
  int size_tcp;
  int size_payload = frag_len;

  if (payload[0] != TLS_HANDSHAKE) {
    DEBUG("Not a TLS handshake: 0x%02hhx\n", payload[0]);
    return -1;
  }

  u_short proto_version = payload[1]*256 + payload[2];
  DEBUG("%s ", ssl_version(proto_version));
  u_short hello_version = payload[OFFSET_HELLO_VERSION]*256 + payload[OFFSET_HELLO_VERSION+1];

  if (proto_version < SSL_MIN_GOOD_VERSION || proto_version >= SSL_MAX_GOOD_VERSION ||
      hello_version < SSL_MIN_GOOD_VERSION || hello_version >= SSL_MAX_GOOD_VERSION) {
    DEBUG("%s bad version(s)\n", ssl_version(hello_version));
    return -1;
  }

  sig->request_version = hello_version;

  if (sig->request_version != record_version) {
    sig->flags |= SSL_FLAG_VER;
  }

  // skip session ID
  const u_char *cipher_data = &payload[OFFSET_SESSION_LENGTH];
  if (size_payload < OFFSET_SESSION_LENGTH + cipher_data[0] + 3) {
    DEBUG("SessionID too long: %hhu bytes (max %hhu)\n", cipher_data[0], OFFSET_SESSION_LENGTH + cipher_data[0] + 3);
    return -1;
  }

  sig->remote_time = 0;
  sig->recv_time = 0;

  cipher_data += 1 + cipher_data[0];

  u_short cs_len;

  switch (payload[5]) {
    case TLS_CLIENT_HELLO:
      cs_len = cipher_data[0]*256 + cipher_data[1];
      sig->cipher_suites = ck_alloc(((cs_len / 2) + 1) * sizeof(u32));
      cipher_data += 2; // skip cipher suites length
      // FIXME: check for buffer overruns
      int cs_id;
      for (cs_id = 0; cs_id < cs_len/2; cs_id++) {
        sig->cipher_suites[cs_id] = (cipher_data[2*cs_id] << 8) | cipher_data[2*cs_id + 1];
        DEBUG(":%02hhX%02hhX", cipher_data[2*cs_id], cipher_data[2*cs_id + 1]);
      }
      sig->cipher_suites[cs_len/2] = END_MARKER;
      DEBUG(":\n");
      break;
    default:
      DEBUG("Not a ClientHello\n");
      return -1;
  }


  // skip copression
  const u_char *extension_data = &cipher_data[cs_len];

  extension_data = extension_data + 1 + extension_data[0];
  u_short extensions_len = (extension_data[0] << 8) + extension_data[1];
  extension_data += 2;

  u_short offset = 0;
  u32 ext_capacity = 5;
  u_short extension_count = 0;
  DEBUG("extensions len %u ", extensions_len);
  sig->extensions = ck_alloc(TLS_EXT_MAX + 1);
  while(offset < extensions_len) {
      if (extension_count >= TLS_EXT_MAX)
        break;
      sig->extensions[extension_count] = (extension_data[offset] << 8) + extension_data[offset + 1];
      u_short len = (extension_data[offset + 2] << 8) + extension_data[offset + 3];
      DEBUG(":%02hhX%02hhX (+%u)", (extension_data[offset] << 8), extension_data[offset + 1], len);
      offset += len + 4;      
      extension_count += 1;
  }
  DEBUG(":\n");
  sig->extensions[extension_count] = END_MARKER;

  return 1;
}


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

    if (record_version >= 0x301) {
      success = fingerprint_tls(&sig, f->request, fragment_len + sizeof(struct ssl3_record_hdr),
                                record_version,
                                f->client->last_seen);
    } else {
      success = fingerprint_ssl_v3(&sig, fragment, fragment_len,
                                   record_version,
                                   f->client->last_seen);
    }

    

  }

  if (success != 1) {

    DEBUG("[#] Does not look like SSLv3/TLS.\n");

    f->in_ssl = -1;
    return 0;

  }


  f->in_ssl = 1;

  fingerprint_ssl(to_srv, f, &sig);

  raw_sig = dump_sig(&sig, 0);
  p = strncpy(
    (char*)f->client->ssl_signature,
    raw_sig,
    (strlen(raw_sig) > SIGNATURE_LENGTH ? SIGNATURE_LENGTH : strlen(raw_sig)) + 1
  );


  if (sig.remote_time && !(sig.flags & SSL_FLAG_RTIME)) {
    f->client->ssl_remote_time         = sig.remote_time;
    f->client->ssl_remote_time_drift   = sig.remote_time - sig.recv_time;
  }


  ck_free(sig.cipher_suites);
  ck_free(sig.extensions);

  return 0;

}
