/*
   p0f - API query code
   --------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#define _FROM_API

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>

#include "tcp.h"
#include "types.h"
#include "config.h"
#include "debug.h"
#include "alloc-inl.h"
#include "p0f.h"
#include "api.h"
#include "process.h"
#include "readfp.h"

/* Process API queries. */

const char http_200_response[] = "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n";
const char http_404_response[] = "HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Type: text/html\r\n\r\nNot Found";
const char http_500_response[] = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n";
const char http_501_response[] = "HTTP/1.1 501 Not Implemented\r\nConnection: close\r\nContent-Type: text/html\r\n\r\nNot Implemented";

u8* append(u8* output, u8* input) {
      strncpy((char*)output, (char*)input, strlen(input));
      return output + strlen(input);
}

u8 handle_query(u8* q, u8* r) {
  u8 ip_ver;
  u8 cli_addr[16];
  struct host_data* h;

  u8* response_start;


  u32 response_length;

  char method[HTTP_MAX_URL];
  char uri[HTTP_MAX_URL];
  char query_string[HTTP_MAX_URL];
  char version[HTTP_MAX_URL];

  char param_ip_version[HTTP_MAX_URL];
  char param_ip[HTTP_MAX_URL];

  char tmp[HTTP_MAX_URL];

  char *p, *p2;


  response_start = r;

  memset(r, 0, HTTP_SERVER_OUTPUT_BUFFER_SIZE);

  //TODO: check if query is complete

  sscanf(q, "%s %s %s\n", method, uri, version);

  DEBUG("[X] API Request: %s\n", uri);

  if (strcasecmp(method, "GET")) {
    strncpy((char*)r, http_501_response, sizeof(http_501_response)-1);
    return (http_501_response)-1;
  }

  //split uri, query_string
  p = strchr(uri, '?');

  if (p) {
	strcpy(query_string, p+1);
	*p = '\0';

  } else {
    strcpy(query_string, "");
  }

  // we only support / as uri
  if (strcasecmp(uri, "/")) {
    strncpy((char*)r, http_404_response, sizeof(http_404_response)-1);
    return (http_404_response)-1;
  }

  //extract parameter
  p = strtok(query_string, "&");

  while (p != NULL) {
    p2 = strchr(p, '=');
    if (p2) {
	  strcpy(tmp, p2+1);
	  *p2 = '\0';

      if (!strcasecmp(p, "ip_version")) {
        strcpy(param_ip_version, tmp);

      } else if (!strcasecmp(p, "ip")) {

        strcpy(param_ip, tmp);
      }
    }

    p = strtok(NULL, "&");
  }

  DEBUG("[X] API Request for ip_version: %s, ip: %s\n", param_ip_version, param_ip);

  if (!strcasecmp(param_ip_version, "4")) {
    ip_ver = IP_VER4;

    if (inet_pton(AF_INET, param_ip, cli_addr) <= 0) {
      r = append(r, http_500_response);
      r = append(r, "Could not parse IPv4 address from ip parameter");
     return r - response_start;
    }

  } else if (!strcasecmp(param_ip_version, "6")) {
    ip_ver = IP_VER6;

    if (inet_pton(AF_INET6, param_ip, cli_addr) <= 0) {
      r = append(r, http_500_response);
      r = append(r, "Could not parse IPv6 address from ip parameter");
      return r - response_start;
    }

  } else {
      r = append(r, http_500_response);
      r = append(r, "wrong/missing ip_version");
      return r - response_start;
  }

  h = lookup_host(cli_addr, ip_ver);

  if(!h) {
      r = append(r, http_200_response);
      r = append(r, "{}");

  } else {
    r = append(r, http_200_response);
  }




  return r - response_start;



//  response_length += append(r, h->ssl_raw_sig);


/*

  r->first_seen = h->first_seen;
  r->last_seen  = h->last_seen;
  r->total_conn = h->total_conn;

  if (h->last_name_id != -1) {

    strncpy((char*)r->os_name, (char*)fp_os_names[h->last_name_id],
            P0F_STR_MAX + 1);

    if (h->last_flavor)
       strncpy((char*)r->os_flavor, (char*)h->last_flavor, P0F_STR_MAX + 1);

  }

  if (h->http_name_id != -1) {

    strncpy((char*)r->http_name, (char*)fp_os_names[h->http_name_id],
            P0F_STR_MAX + 1);

    if (h->http_flavor)
      strncpy((char*)r->http_flavor, (char*)h->http_flavor, P0F_STR_MAX + 1);

  }

  if (h->link_type)
    strncpy((char*)r->link_type, (char*)h->link_type, P0F_STR_MAX + 1);

  if (h->language)
    strncpy((char*)r->language, (char*)h->language, P0F_STR_MAX + 1);

  r->bad_sw           = h->bad_sw;
  r->last_nat         = h->last_nat;
  r->last_chg         = h->last_chg;
  r->up_mod_days      = h->up_mod_days;
  r->distance         = h->distance;
  r->os_match_q       = h->last_quality;

  if (h->http_raw_sig)
    strncpy((char*)r->http_raw_sig, (char*)h->http_raw_sig, HTTP_MAX_SHOW + 1);

  r->ssl_remote_time  = h->ssl_remote_time;
  r->ssl_recv_time    = h->ssl_recv_time;



  if (h->last_up_min != -1) r->uptime_min = h->last_up_min;
*/

  return 0;
}
