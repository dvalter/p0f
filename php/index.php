<?php
require_once('p0f_constants.php');
$QUERY_IP = array_key_exists('ip', $_REQUEST) ? $_REQUEST['ip'] : $_SERVER['REMOTE_ADDR'];
?>
<html>
<body>
    <form method="GET">
        IP: <input name="ip" value="<?=$QUERY_IP?>">
        <input type="submit">
    </form>
<?php
ini_set('display_errors', 1);
error_reporting(E_ALL);

$tlsExtensions          = require('tls_extensions.inc.php');
$tlsCipherSuiteRegistry = require('tls_cipher_suite_registry.inc.php');

ob_end_flush();
ob_implicit_flush(true);

$fd = fsockopen("127.0.0.1", "1338");

/*
 * Queries have exactly 21 bytes. The format is:
 *
 * - Magic dword (0x50304601), in native endian of the platform.
 *
 * - Address type byte: 4 for IPv4, 6 for IPv6.
 *
 * - 16 bytes of address data, network endian. IPv4 addresses should be
 *  aligned to the left. (big endian left align)
 *
 */
$query = pack("LCNNNN",
    0x50304601,
    4, /* IPv4 */
    ip2long($QUERY_IP),
    0,
    0,
    0
);

fwrite($fd, $query);
$r =  fgets($fd, SIZEOF_P0F_API_RESPONSE);
fclose($fd);

$resp = unpack(
    "Lmagic/"  .          // Must be P0F_RESP_MAGIC
    "Lstatus/" .          // P0F_STATUS_*
    "Lfirst_seen/" .      // First seen (unix time)
    "Llast_seen/" .       // Last seen (unix time)
    "Ltotal_conn/".       // Total connections seen
    "Luptime_min/" .      // Last uptime (minutes)
    "Lup_mod_days/" .     // Uptime modulo (days)
    "Llast_nat/" .        // NAT / LB last detected (unix time)
    "Llast_chg/" .        // OS chg last detected (unix time)
    "Sdistance/" .        // System distance
    "Cbad_sw/" .          // Host is lying about U-A / Server
    "Cos_match_q/" .      // Match quality
    "a32os_name/" .       // Name of detected OS
    "a32os_flavor/" .     // Flavor of detected OS
    "a32http_name/" .     // Name of detected HTTP app
    "a32http_flavor/" .   // Flavor of detected HTTP app
    "a32link_type/" .     // Link type
    "a32language/" .      // Language
    "a" . (HTTP_MAX_SHOW + 1) . "http_raw_sig/" .    // http raw signature
    "Lssl_remote_time/" . // Last client timestamp from SSL
    "Lssl_recv_time/" .    // Language
    "a" . (HTTP_MAX_SHOW + 1) . "ssl_raw_sig",    // ssl client handshake raw signature
    $r
);

foreach(array('os_name', 'os_flavor', 'http_name', 'http_flavor', 'link_type', 'language', 'ssl_raw_sig') as $field) {
    $resp[$field] = trim($resp[$field]);
}

if($resp["status"] == P0F_STATUS_BADQUERY) {
    echo "bad query";
    exit;
} elseif ($resp["status"] == P0F_STATUS_NOMATCH) {
    echo "no match";
    exit;
}

unset($resp['magic']);
unset($resp['status']);

?>
<h2>Fingerprint Match</h2>
<table border="1">
<?php foreach ($resp as $key => $value) {
    if(in_array($key, array('first_seen', 'last_seen', 'ssl_remote_time', 'ssl_recv_time'))) {
        if($value == 0) {
            $value = "";
        } else {
            $value = date("Y-m-d H:i:s", $value);
        }
    }
?>
    <tr><td><?=$key?></td><td><?=$value?></td></tr>

<?php
}
?>
</table>
<?php
if (trim($resp["http_raw_sig"]) != "") {
    list($ver, $horder, $habsent, $expsw) = explode(":", $resp['http_raw_sig']);

    $horder = preg_replace("/,(?![^\[\]]*\])/", "<br/>", $horder);
?>
    <h2>HTTP Info</h2>
    <table border=1>
        <tr><td>Version</td><td><?=$ver?></td></tr>
        <tr><td>Present Headers</td><td><?=$horder?></td></tr>
        <tr><td>Absent Headers</td><td><?=$habsent?></td></tr>
        <tr><td>User-Agent</td><td><?=$expsw?></td></tr>
    </table>
<?php
}

if (trim($resp["ssl_raw_sig"]) != "") {
    list($sslver, $ciphers, $extensions, $sslflags) = explode(":", $resp['ssl_raw_sig']);

    $ciphers = implode("<br/>",array_map(function($cipher) use ($tlsCipherSuiteRegistry) {
        $cipher = hexdec($cipher);
        return array_key_exists($cipher, $tlsCipherSuiteRegistry) ? $tlsCipherSuiteRegistry[$cipher] : $cipher;
    }, explode(",", $ciphers)));

    $extensions = implode("<br/>",array_map(function($extension) use ($tlsExtensions) {
        $extension = hexdec($extension);
        return array_key_exists($extension, $tlsExtensions) ? $tlsExtensions[$extension] : $extension;
    }, explode(",", $extensions)));

    ?>
<h2>SSL Info</h2>
<table border=1>
    <tr><td>Version</td><td><?=$sslver?></td></tr>
    <tr><td>Ciphers</td><td><?=$ciphers?></td></tr>
    <tr><td>Extensions</td><td><?=$extensions?></td></tr>
    <tr><td>Flags</td><td><?=$sslflags?></td></tr>
</table>

<?php
}

?>