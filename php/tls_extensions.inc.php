<?php
//see http://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xml

return array(
    0   => "server_name",
    1   => "max_fragment_length",
    2   => "client_certificate_url",
    3   => "trusted_ca_keys",
    4   => "truncated_hmac",
    5   => "status_request",
    6   => "user_mapping",
    7   => "client_authz",
    8   => "server_authz",
    9   => "cert_type",
    10  => "elliptic_curves",
    11  => "ec_point_formats",
    12  => "srp",
    13  => "signature_algorithms",
    14  => "use_srtp",
    15  => "heartbeat",
    16  => "application_layer_protocol_negotiation",
    17  => "status_request_v2",
    18  => "signed_certificate_timestamp",
    19  => "client_certificate_type",
    20  => "server_certificate_type",
    21  => "padding", # temporary till 2015-03-12
    22  => "encrypt_then_mac", # temporary till 2015-06-05
    35  => "SessionTicket TLS",
    40  => "extended_random",
    13172 => "next_protocol_negotiation",
    13175 => "origin_bound_certificates",
    13180 => "encrypted_client_certificates",
    30031 => "channel_id",
    30032 => "channel_id_new",
    35655 => "padding",
    65281 => "renegotiation_info"
);