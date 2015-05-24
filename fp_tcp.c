/*
   p0f - TCP/IP packet matching
   ----------------------------

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
#include "hash.h"
#include "tcp.h"
#include "p0f.h"

#include "fp_tcp.h"

/* TCP signature buckets: */

static struct tcp_sig_record* sigs[2][SIG_BUCKETS];
static u32 sig_cnt[2][SIG_BUCKETS];


/* Figure out what the TTL distance might have been for an unknown sig. */

static u8 guess_dist(u8 ttl) {
  if (ttl <= 32) return 32 - ttl;
  if (ttl <= 64) return 64 - ttl;
  if (ttl <= 128) return 128 - ttl;
  return 255 - ttl;
}


/* Figure out if window size is a multiplier of MSS or MTU. We don't take window
   scaling into account, because neither do TCP stack developers. */

static s16 detect_win_multi(struct tcp_sig* ts, u8* use_mtu, u16 syn_mss) {

  u16 win = ts->win;
  s32 mss = ts->mss, mss12 = mss - 12;

  if (!win || mss < 100 || ts->win_type != WIN_TYPE_NORMAL)
    return -1;

#define RET_IF_DIV(_div, _use_mtu, _desc) do { \
    if ((_div) && !(win % (_div))) { \
      *use_mtu = (_use_mtu); \
      DEBUG("[#] Window size %u is a multiple of %s [%u].\n", win, _desc, _div); \
      return win / (_div); \
    } \
  } while (0)

  RET_IF_DIV(mss, 0, "MSS");

  /* Some systems will sometimes subtract 12 bytes when timestamps are in use. */

  if (ts->ts1) RET_IF_DIV(mss12, 0, "MSS - 12");

  /* Some systems use MTU on the wrong interface, so let's check for the most
     common case. */

  RET_IF_DIV(1500 - MIN_TCP4, 0, "MSS (MTU = 1500, IPv4)");
  RET_IF_DIV(1500 - MIN_TCP4 - 12, 0, "MSS (MTU = 1500, IPv4 - 12)");

  if (ts->ip_ver == IP_VER6) {

    RET_IF_DIV(1500 - MIN_TCP6, 0, "MSS (MTU = 1500, IPv6)");
    RET_IF_DIV(1500 - MIN_TCP6 - 12, 0, "MSS (MTU = 1500, IPv6 - 12)");

  }

  /* Some systems use MTU instead of MSS: */

  RET_IF_DIV(mss + MIN_TCP4, 1, "MTU (IPv4)");
  RET_IF_DIV(mss + ts->tot_hdr, 1, "MTU (actual size)");
  if (ts->ip_ver == IP_VER6) RET_IF_DIV(mss + MIN_TCP6, 1, "MTU (IPv6)");
  RET_IF_DIV(1500, 1, "MTU (1500)");

  /* On SYN+ACKs, some systems use of the peer: */

  if (syn_mss) {

    RET_IF_DIV(syn_mss, 0, "peer MSS");
    RET_IF_DIV(syn_mss - 12, 0, "peer MSS - 12");

  }

#undef RET_IF_DIV

  return -1;

}

/* Convert struct packet_data to a simplified struct tcp_sig representation
   suitable for signature matching. Compute hashes. */

static void packet_to_sig(struct packet_data* pk, struct tcp_sig* ts) {

  ts->opt_hash = hash32(pk->opt_layout, pk->opt_cnt, hash_seed);

  ts->quirks      = pk->quirks;
  ts->opt_eol_pad = pk->opt_eol_pad;
  ts->ip_opt_len  = pk->ip_opt_len;
  ts->ip_ver      = pk->ip_ver;
  ts->ttl         = pk->ttl;
  ts->mss         = pk->mss;
  ts->win         = pk->win;
  ts->win_type    = WIN_TYPE_NORMAL; /* Keep as-is. */
  ts->wscale      = pk->wscale;
  ts->pay_class   = !!pk->pay_len;
  ts->tot_hdr     = pk->tot_hdr;
  ts->ts1         = pk->ts1;
  ts->recv_ms     = get_unix_time_ms();
  ts->matched     = NULL;
  ts->fuzzy       = 0;
  ts->dist        = 0;

};


/* Dump unknown signature. */

static u8* dump_sig(struct packet_data* pk, struct tcp_sig* ts, u16 syn_mss) {

  static u8* ret;
  u32 rlen = 0;

  u8  win_mtu;
  s16 win_m;
  u32 i;
  u8  dist = guess_dist(pk->ttl);

#define RETF(_par...) do { \
    s32 _len = snprintf(NULL, 0, _par); \
    if (_len < 0) FATAL("Whoa, snprintf() fails?!"); \
    ret = DFL_ck_realloc_kb(ret, rlen + _len + 1); \
    snprintf((char*)ret + rlen, _len + 1, _par); \
    rlen += _len; \
  } while (0)

  if (dist > MAX_DIST) {

    RETF("%u:%u+?:%u:", pk->ip_ver, pk->ttl, pk->ip_opt_len);

  } else {

    RETF("%u:%u+%u:%u:", pk->ip_ver, pk->ttl, dist, pk->ip_opt_len);

  }

  /* Detect a system echoing back MSS from p0f-sendsyn queries, suggest using
     a wildcard in such a case. */

  if (pk->mss == SPECIAL_MSS && pk->tcp_type == (TCP_SYN|TCP_ACK)) RETF("*:");
  else RETF("%u:", pk->mss);

  win_m = detect_win_multi(ts, &win_mtu, syn_mss);

  if (win_m > 0) RETF("%s*%u", win_mtu ? "mtu" : "mss", win_m);
  else RETF("%u", pk->win);

  RETF(",%u:", pk->wscale);

  for (i = 0; i < pk->opt_cnt; i++) {

    switch (pk->opt_layout[i]) {

      case TCPOPT_EOL:
        RETF("%seol+%u", i ? "," : "", pk->opt_eol_pad); break;

      case TCPOPT_NOP:
        RETF("%snop", i ? "," : ""); break;

      case TCPOPT_MAXSEG:
        RETF("%smss", i ? "," : ""); break;

      case TCPOPT_WSCALE:
        RETF("%sws", i ? "," : ""); break;

      case TCPOPT_SACKOK:
        RETF("%ssok", i ? "," : ""); break;

      case TCPOPT_SACK:
        RETF("%ssack", i ? "," : ""); break;

      case TCPOPT_TSTAMP:
        RETF("%sts", i ? "," : ""); break;

      default:
        RETF("%s?%u", i ? "," : "", pk->opt_layout[i]);

    }

  }

  RETF(":");

  if (pk->quirks) {

    u8 sp = 0;

#define MAYBE_CM(_str) do { \
    if (sp) RETF("," _str); else RETF(_str); \
    sp = 1; \
  } while (0)

    if (pk->quirks & QUIRK_DF)      MAYBE_CM("df");
    if (pk->quirks & QUIRK_NZ_ID)   MAYBE_CM("id+");
    if (pk->quirks & QUIRK_ZERO_ID) MAYBE_CM("id-");
    if (pk->quirks & QUIRK_ECN)     MAYBE_CM("ecn");
    if (pk->quirks & QUIRK_NZ_MBZ)  MAYBE_CM("0+");
    if (pk->quirks & QUIRK_FLOW)    MAYBE_CM("flow");

    if (pk->quirks & QUIRK_ZERO_SEQ) MAYBE_CM("seq-");
    if (pk->quirks & QUIRK_NZ_ACK)   MAYBE_CM("ack+");
    if (pk->quirks & QUIRK_ZERO_ACK) MAYBE_CM("ack-");
    if (pk->quirks & QUIRK_NZ_URG)   MAYBE_CM("uptr+");
    if (pk->quirks & QUIRK_URG)      MAYBE_CM("urgf+");
    if (pk->quirks & QUIRK_PUSH)     MAYBE_CM("pushf+");

    if (pk->quirks & QUIRK_OPT_ZERO_TS1) MAYBE_CM("ts1-");
    if (pk->quirks & QUIRK_OPT_NZ_TS2)   MAYBE_CM("ts2+");
    if (pk->quirks & QUIRK_OPT_EOL_NZ)   MAYBE_CM("opt+");
    if (pk->quirks & QUIRK_OPT_EXWS)     MAYBE_CM("exws");
    if (pk->quirks & QUIRK_OPT_BAD)      MAYBE_CM("bad");

#undef MAYBE_CM

  }

  if (pk->pay_len) RETF(":+"); else RETF(":0");

  return ret;

}


/* Dump signature-related flags. */

static u8* dump_flags(struct packet_data* pk, struct tcp_sig* ts) {

  static u8* ret;
  u32 rlen = 0;

  RETF("");

  if (ts->matched) {

    if (ts->matched->generic) RETF(" generic");
    if (ts->fuzzy) RETF(" fuzzy");
    if (ts->matched->bad_ttl) RETF(" random_ttl");

  }

  if (ts->dist > MAX_DIST) RETF(" excess_dist");
  if (pk->tos) RETF(" tos:0x%02x", pk->tos);

  if (*ret) return ret + 1; else return (u8*)"none";

#undef RETF

}

/* Fingerprint SYN or SYN+ACK. */

struct tcp_sig* fingerprint_tcp(u8 to_srv, struct packet_data* pk,
                                struct packet_flow* f) {

  struct tcp_sig* sig;
  struct tcp_sig_record* m;

  sig = ck_alloc(sizeof(struct tcp_sig));
  packet_to_sig(pk, sig);

  /* Detect packets generated by p0f-sendsyn; they require special
     handling to provide the user with response fingerprints, but not
     interfere with NAT scores and such. */

  if (pk->tcp_type == TCP_SYN && pk->win == SPECIAL_WIN &&
      pk->mss == SPECIAL_MSS) f->sendsyn = 1;

  if (to_srv) 
    start_observation(f->sendsyn ? "sendsyn probe" : "syn", 4, 1, f);
  else
    start_observation(f->sendsyn ? "sendsyn response" : "syn+ack", 4, 0, f);


  add_observation_field("os", NULL);

  if (m && m->bad_ttl) {

    OBSERVF("dist", "<= %u", sig->dist);

  } else {

    if (to_srv) f->client->distance = sig->dist;
    else f->server->distance = sig->dist;
    
    OBSERVF("dist", "%u", sig->dist);

  }

  add_observation_field("params", dump_flags(pk, sig));

  u8 *raw_sig = dump_sig(pk, sig, f->syn_mss);
  u8 *p;

  p = strncpy(
    to_srv ? (char*)f->client->tcp_signature : (char*)f->server->tcp_signature,
    raw_sig,
    strlen(raw_sig) > SIGNATURE_LENGTH ? SIGNATURE_LENGTH : strlen(raw_sig)
  );
  p = "\0";

  add_observation_field("raw_sig", raw_sig);

  if (pk->tcp_type == TCP_SYN) f->syn_mss = pk->mss;

  /* That's about as far as we go with non-OS signatures. */

  if (m && m->class_id == -1) {
    ck_free(sig);
    return NULL;
  }

  if (f->sendsyn) {
    ck_free(sig);
    return NULL;
  }

  return sig;

}


/* Perform uptime detection. This is the only FP function that gets called not
   only on SYN or SYN+ACK, but also on ACK traffic. */

void check_ts_tcp(u8 to_srv, struct packet_data* pk, struct packet_flow* f) {

  u32    ts_diff;
  u64    ms_diff;

  u32    freq;
  u32    up_min, up_mod_days;

  double ffreq;

  if (!pk->ts1 || f->sendsyn) return;

  /* If we're getting SYNs very rapidly, last_syn may be changing too quickly
     to be of any use. Perhaps lock into an older value? */

  if (to_srv) {

     if (f->cli_tps || !f->client->last_syn || !f->client->last_syn->ts1)
       return;

     ms_diff = get_unix_time_ms() - f->client->last_syn->recv_ms;
     ts_diff = pk->ts1 - f->client->last_syn->ts1;

  } else {

     if (f->srv_tps || !f->server->last_synack || !f->server->last_synack->ts1)
        return;

     ms_diff = get_unix_time_ms() - f->server->last_synack->recv_ms;
     ts_diff = pk->ts1 - f->server->last_synack->ts1;
  
  }

  /* Wait at least 25 ms, and not more than 10 minutes, for at least 5
     timestamp ticks. Allow the timestamp to go back slightly within
     a short window, too - we may be receiving packets a bit out of
     order. */

  if (ms_diff < MIN_TWAIT || ms_diff > MAX_TWAIT) return;

  if (ts_diff < 5 || (ms_diff < TSTAMP_GRACE && (~ts_diff) / 1000 < 
      MAX_TSCALE / TSTAMP_GRACE)) return;

  if (ts_diff > ~ts_diff) ffreq = ~ts_diff * -1000.0 / ms_diff;
  else ffreq = ts_diff * 1000.0 / ms_diff;

  if (ffreq < MIN_TSCALE || ffreq > MAX_TSCALE) {

    /* Allow bad reading on SYN, as this may be just an artifact of IP
       sharing or OS change. */

    if (pk->tcp_type != TCP_SYN) {

      if (to_srv) f->cli_tps = -1; else f->srv_tps = -1;

    }

    DEBUG("[#] Bad %s TS frequency: %.02f Hz (%d ticks in %llu ms).\n",
          to_srv ? "client" : "server", ffreq, ts_diff, ms_diff);

    return;

  }

  freq = ffreq;

  /* Round the frequency neatly. */

  switch (freq) {

    case 0:           freq = 1; break;
    case 1 ... 10:    break;
    case 11 ... 50:   freq = (freq + 3) / 5 * 5; break;
    case 51 ... 100:  freq = (freq + 7) / 10 * 10; break;
    case 101 ... 500: freq = (freq + 33) / 50 * 50; break;
    default:          freq = (freq + 67) / 100 * 100; break;

  }

  if (to_srv) f->cli_tps = freq; else f->srv_tps = freq;

  up_min = pk->ts1 / freq / 60;
  up_mod_days = 0xFFFFFFFF / (freq * 60 * 60 * 24);

  start_observation("uptime", 2, to_srv, f);

  if (to_srv) {

    f->client->last_up_min = up_min;
    f->client->up_mod_days = up_mod_days;

  } else {

    f->server->last_up_min = up_min;
    f->server->up_mod_days = up_mod_days;

  }

  OBSERVF("uptime", "%u days %u hrs %u min (modulo %u days)",
          (up_min / 60 / 24), (up_min / 60) % 24, up_min % 60,
          up_mod_days);

  OBSERVF("raw_freq", "%.02f Hz", ffreq);

}
