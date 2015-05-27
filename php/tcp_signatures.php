<?php
return array(
    array(
        'name'        => 'Linux:3.11 and newer',
        'signature'   => '4:64:mss*20,10:mss,sok,ts,nop,ws:df,id+'
    ),
    array(
        'name'        => 'Linux:3.11 and newer',
        'signature'   => '4:64:mss*20,7:mss,sok,ts,nop,ws:df,id+'
    ),

    array(
        'name'        => 'Linux:3.1-3.10',
        'signature'   => '4:64:mss*10,4:mss,sok,ts,nop,ws:df,id+'
    ),
    array(
        'name'        => 'Linux:3.1-3.10',
        'signature'   => '4:64:mss*10,5:mss,sok,ts,nop,ws:df,id+'
    ),
    array(
        'name'        => 'Linux:3.1-3.10',
        'signature'   => '4:64:mss*10,6:mss,sok,ts,nop,ws:df,id+'
    ),
    array(
        'name'        => 'Linux:3.1-3.10',
        'signature'   => '4:64:mss*10,7:mss,sok,ts,nop,ws:df,id+'
    ),

    array(
        'name'        => 'Linux:2.6.x',
        'signature'   => '4:64:mss*4,6:mss,sok,ts,nop,ws:df,id+'
    ),
    array(
        'name'        => 'Linux:2.6.x',
        'signature'   => '4:64:mss*4,7:mss,sok,ts,nop,ws:df,id+'
    ),
    array(
        'name'        => 'Linux:2.6.x',
        'signature'   => '4:64:mss*4,8:mss,sok,ts,nop,ws:df,id+'
    ),


    array(
        'name'        => 'Linux:2.4.x',
        'signature'   => '4:64:mss*4,0:mss,sok,ts,nop,ws:df,id+'
    ),
    array(
        'name'        => 'Linux:2.4.x',
        'signature'   => '4:64:mss*4,1:mss,sok,ts,nop,ws:df,id+'
    ),
    array(
        'name'        => 'Linux:2.4.x',
        'signature'   => '4:64:mss*4,2:mss,sok,ts,nop,ws:df,id+'
    ),

    //Catch-All Rules
    array(
        'name'        => 'Linux:3.x',
        'signature'   => '4:64:mss*10,*:mss,sok,ts,nop,ws:df,id+'
    ),
    array(
        'name'        => 'Linux:2.4.x-2.6.x',
        'signature'   => '4:64:mss*4,*:mss,sok,ts,nop,ws:df,id+'
    ),
    array(
        'name'        => 'Linux:2.2.x-3.x',
        'signature'   => '4:64:*,*:mss,sok,ts,nop,ws:df,id+'
    ),
    array(
        'name'        => 'Linux:2.2.x-3.x (no timestamps)',
        'signature'   => '4:64:*,*:mss,nop,nop,sok,nop,ws:df,id+'
    ),
    array(
        'name'        => 'Linux:2.2.x-3.x (barebone)',
        'signature'   => '4:64:*,0:mss:df,id+'
    )


);

/*
 *
; -------
; Windows
; -------

label = s:win:Windows:XP
sig   = *:128:16384,0:mss,nop,nop,sok:df,id+
sig   = *:128:65535,0:mss,nop,nop,sok:df,id+
sig   = *:128:65535,0:mss,nop,ws,nop,nop,sok:df,id+
sig   = *:128:65535,1:mss,nop,ws,nop,nop,sok:df,id+
sig   = *:128:65535,2:mss,nop,ws,nop,nop,sok:df,id+

label = s:win:Windows:7 or 8
sig   = *:128:8192,0:mss,nop,nop,sok:df,id+
sig   = *:128:8192,2:mss,nop,ws,nop,nop,sok:df,id+
sig   = *:128:8192,8:mss,nop,ws,nop,nop,sok:df,id+
sig   = *:128:8192,2:mss,nop,ws,sok,ts:df,id+


; Catch-all:

label = g:win:Windows:NT kernel 5.x
sig   = *:128:16384,*:mss,nop,nop,sok:df,id+
sig   = *:128:65535,*:mss,nop,nop,sok:df,id+
sig   = *:128:16384,*:mss,nop,ws,nop,nop,sok:df,id+
sig   = *:128:65535,*:mss,nop,ws,nop,nop,sok:df,id+

label = g:win:Windows:NT kernel 6.x
sig   = *:128:8192,*:mss,nop,nop,sok:df,id+
sig   = *:128:8192,*:mss,nop,ws,nop,nop,sok:df,id+

label = g:win:Windows:NT kernel
sig   = *:128:*,*:mss,nop,nop,sok:df,id+
sig   = *:128:*,*:mss,nop,ws,nop,nop,sok:df,id+

; ------
; Mac OS
; ------

label = s:unix:Mac OS X:10.x
sig   = *:64:65535,1:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+
sig   = *:64:65535,3:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+

label = s:unix:MacOS X:10.9 or newer (sometimes iPhone or iPad)
sig   = *:64:65535,4:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+

label = s:unix:iOS:iPhone or iPad
sig   = *:64:65535,2:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+

; Catch-all rules:

label = g:unix:Mac OS X:
sig   = *:64:65535,*:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+

; -------
; FreeBSD
; -------

label = s:unix:FreeBSD:9.x or newer
sig   = *:64:65535,6:mss,nop,ws,sok,ts:df,id+

label = s:unix:FreeBSD:8.x
sig   = *:64:65535,3:mss,nop,ws,sok,ts:df,id+

; Catch-all rules:

label = g:unix:FreeBSD:
sig   = *:64:65535,*:mss,nop,ws,sok,ts:df,id+

; -------
; OpenBSD
; -------

label = s:unix:OpenBSD:3.x
sig   = *:64:16384,0:mss,nop,nop,sok,nop,ws,nop,nop,ts:df,id+

label = s:unix:OpenBSD:4.x-5.x
sig   = *:64:16384,3:mss,nop,nop,sok,nop,ws,nop,nop,ts:df,id+

; -------
; Solaris
; -------

label = s:unix:Solaris:8
sig   = *:64:32850,1:nop,ws,nop,nop,ts,nop,nop,sok,mss:df,id+

label = s:unix:Solaris:10
sig   = *:64:mss*34,0:mss,nop,ws,nop,nop,sok:df,id+



 */