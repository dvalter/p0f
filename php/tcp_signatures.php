<?php
return array(
    '4:64:mss,sok,ts,nop,ws:df,id+'                  => 'Linux',
    '4:64:mss,nop,nop,sok,nop,ws:df,id+'             => 'Linux',
    '4:64:mss:df,id+'                                => 'Linux',

    '4:128:mss,nop,nop,sok:df,id+'                   => 'Windows NT, XP, 7 or 8',
    '4:128:mss,nop,ws,nop,nop,sok:df,id+'            => 'Windows NT, XP, 7 or 8',
    '4:128:mss,nop,ws,sok,ts:df,id+'                 => 'Windows NT, XP, 7 or 8',

    '4:64:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+'   => 'MacOS X 10.9 or newer (sometimes iPhone or iPad)',

    '4:64:mss,nop,ws,sok,ts:df,id+'                 => 'FreeBSD',

    '4:64:mss,nop,nop,sok,nop,ws,nop,nop,ts:df,id+' => 'OpenBSD',

    '4:64:nop,ws,nop,nop,ts,nop,nop,sok,mss:df,id+' => 'Solaris',
    '4:64:mss,nop,ws,nop,nop,sok:df,id+'            => 'Solaris'
);