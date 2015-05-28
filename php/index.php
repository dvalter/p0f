<?php
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
$tcpSignatures          = require('tcp_signatures.php');
$mtuSignatures          = require('mtu_signatures.php');

ob_end_flush();
ob_implicit_flush(true);

$resp = (array)json_decode(
    file_get_contents("http://127.0.0.1:1338/?ip=" . $QUERY_IP . "&ip_version=4")
);

?>
<h2>Fingerprint Matching</h2>
<table border="1">
    <tr><td>OS guess (based on TCP data)</td><td><?=array_key_exists($resp["tcp_signature"], $tcpSignatures) ? $tcpSignatures[$resp["tcp_signature"]] : 'Unknown' ?></td></tr>
    <tr><td>Link guess (based on MTU)</td><td><?=array_key_exists($resp['mtu'], $mtuSignatures) ? $mtuSignatures[$resp['mtu']] : 'Unknown' ?></td></tr>
</table>

<h2>Connection Info</h2>
<table border="1">

<?php foreach ($resp as $key => $value) {
    if(in_array($key, array(
        'http_signature', 'ssl_signature', 'ssl_remote_time', 'tcp_signature'
    ))) continue;

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
if ($resp["tcp_signature"] != "") {
    list($ver, $ittl, $olayout, $quirks) = explode("|", $resp['tcp_signature']);
?>
    <h2>TCP Info</h2>
    <table border=1>
        <tr><td>TCP Signature</td><td><?=$resp["tcp_signature"]?></td></tr>
        <tr><td>IP Version</td><td><?=$ver?></td></tr>
        <tr><td>Initial TTL used by the OS</td><td><?=$ittl?></td></tr>
        <tr><td>TCP options</td><td><?=$olayout?></td></tr>
        <tr><td>Quirks</td><td><?=$quirks?></td></tr>
    </table>
<?php
}

if (trim($resp["http_signature"]) != "") {
    list($ver, $horder, $expsw) = explode("|", $resp['http_signature']);

    $horder = preg_replace("/,(?![^\[\]]*\])/", "<br/>", $horder);
?>
    <h2>HTTP Info</h2>
    <table border=1>
        <tr><td>HTTP Signature</td><td><?=$resp["http_signature"]?></td></tr>
        <tr><td>Version</td><td>HTTP 1.<?=$ver?></td></tr>
        <tr><td>Present Headers</td><td><?=$horder?></td></tr>
        <tr><td>User-Agent</td><td><?=$expsw?></td></tr>
    </table>
<?php
}

if (trim($resp["ssl_signature"]) != "") {
    list($sslver, $ciphers, $extensions, $sslflags) = explode("|", $resp['ssl_signature']);

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
    <tr><td>SSL Signature</td><td><?=$resp["ssl_signature"]?></td></tr>
    <tr><td>Version</td><td><?=$sslver?></td></tr>
    <tr><td>Ciphers</td><td><?=$ciphers?></td></tr>
    <tr><td>Extensions</td><td><?=$extensions?></td></tr>
    <tr><td>Flags</td><td><?=$sslflags?></td></tr>
</table>

<?php
}
?>