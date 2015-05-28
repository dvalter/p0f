/*
   p0f - API query code
   --------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#define _FROM_API

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

/* Process API queries. */

const char http_200_response[] = "HTTP/1.0 200 OK\r\nConnection: close\r\nContent-Type: application/json\r\n\r\n";
const char http_401_response[] = "HTTP/1.0 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"secured\"\r\nConnection: close\r\nContent-Type: text/html\r\n\r\nUnauhorized";
const char http_404_response[] = "HTTP/1.0 404 Not Found\r\nConnection: close\r\nContent-Type: text/html\r\n\r\nNot Found";
const char http_500_response[] = "HTTP/1.0 500 Internal Server Error\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n";
const char http_501_response[] = "HTTP/1.0 501 Not Implemented\r\nConnection: close\r\nContent-Type: text/html\r\n\r\nNot Implemented";

u8* append(u8* r, u8* input) {
      strncpy((char*)r, (char*)input, strlen(input));
      return r + strlen(input);
}

u8* append_json_u32(u8* r, u8* key, u32 value) {
  u8 string_value[11];
  sprintf(string_value, "%u", value);
  r = append(r, "  \"");
  r = append(r, key);
  r = append(r, "\": ");
  r = append(r, string_value);
  r = append(r, ",\n");
  return r;
}

u8* append_json_s32(u8* r, u8* key, s32 value) {
  u8 string_value[12];
  sprintf(string_value, "%d", value);
  r = append(r, "  \"");
  r = append(r, key);
  r = append(r, "\": ");
  r = append(r, string_value);
  r = append(r, ",\n");
  return r;
}

u8* append_json_string(u8* r, u8* key, u8* value) {
    r = append(r, "  \"");
    r = append(r, key);
    r = append(r, "\": \"");
    r = append(r, value);
    r = append(r, "\",\n");
    return r;
}

s32 handle_query(u8* q, u8* r) {
  u8 ip_ver;
  u8 cli_addr[16];
  struct host_data* h;

  u8* response_start;


  u32 response_length;

  char method[HTTP_MAX_URL];
  char uri[HTTP_MAX_URL];
  char query_string[HTTP_MAX_URL];
  char version[HTTP_MAX_URL];

  char param_ip[HTTP_MAX_URL];

  char tmp[HTTP_MAX_URL];

  char *p, *p2;

  //check if we received a complete query
  if(!strstr(q, "\r\n\r\n")) {
	  return -1;
  }

  if(http_auth_base64) {
    //respond with unauthorized
    strncpy((char*)r, http_401_response, sizeof(http_401_response)-1);
    return sizeof(http_401_response)-1;
  }

  response_start = r;

  memset(r, 0, HTTP_SERVER_OUTPUT_BUFFER_SIZE);
  memset(param_ip, 0, HTTP_MAX_URL);

  sscanf(q, "%s %s %s\n", method, uri, version);

  DEBUG("[API] API Request: %s\n", uri);

  if (strcasecmp(method, "GET")) {
    strncpy((char*)r, http_501_response, sizeof(http_501_response)-1);
    return sizeof(http_501_response)-1;
  }

  //split uri, query_string
  p = strchr(uri, '?');

  if (p) {
	strcpy(query_string, p+1);
	*p = '\0';

  } else {
    strcpy(query_string, "");
  }

  DEBUG("[API] Query String: %s\n", query_string);

  // we only support / as uri
  if (strcasecmp(uri, "/")) {
    r = append(r, http_404_response);
    return r - response_start;
  }

  //extract parameter
  p = strtok(query_string, "&");

  while (p != NULL) {
      p2 = strchr(p, '=');
      if (p2) {
        strcpy(tmp, p2+1);
        *p2 = '\0';

        if (!strcasecmp(p, "ip")) {
          strcpy(param_ip, tmp);
        }
      }

      p = strtok(NULL, "&");
  }

  p2 = strchr(param_ip, ':');

  //only ipv4 supported atm
  ip_ver = (p2) ? IP_VER6 : IP_VER4;

  DEBUG("[API] API Request for ip_version: %s, ip: %s\n", (ip_ver == IP_VER4) ? "4" : "6", param_ip);


  if (inet_pton(
      AF_INET,
      param_ip,
      cli_addr) <= 0) {
    r = append(r, http_500_response);
    r = append(r, "Could not parse ip address from ip parameter");
    return r - response_start;
  }

  h = lookup_host(cli_addr, ip_ver);

  if(!h) {
      r = append(r, http_200_response);
      r = append(r, "{}");

  } else {
    r = append(r, http_200_response);
    r = append(r, "{\n");

    r = append_json_s32     (r, "fp_uptime_minutes",         h->last_up_min);
    r = append_json_u32     (r, "fp_uptime_mod_days",        h->up_mod_days);

    r = append_json_u32     (r, "fp_first_seen",             h->first_seen);
    r = append_json_u32     (r, "fp_last_seen",              h->last_seen);
    r = append_json_u32     (r, "fp_total_conn",             h->total_conn);

    r = append_json_string  (r, "fp_tcp_signature",         &h->tcp_signature);

    r = append_json_u32     (r, "fp_distance",               h->distance);
    r = append_json_u32     (r, "fp_mtu",                    h->mtu);

    r = append_json_string  (r, "fp_http_signature",         &h->http_signature);

    r = append_json_string  (r, "fp_ssl_signature",          &h->ssl_signature);
    r = append_json_u32     (r, "fp_ssl_remote_time",         h->ssl_remote_time);
    r = append_json_s32     (r, "fp_ssl_remote_time_drift",   h->ssl_remote_time_drift);


    //remove last comma
    r = r - 2;
    *r = '\n';
    r = r + 1;

    r = append(r, "}\n");


  }

  return r - response_start;
}
