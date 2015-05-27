[http:request]

ua_os = Linux,Windows,iOS=[iPad],iOS=[iPhone],Mac OS X,FreeBSD,OpenBSD,NetBSD,Solaris=[SunOS]

; -------
; Firefox
; -------

label = s:!:Firefox:2.x
sys   = Windows,@unix
sig   = *:Host,User-Agent,Accept=[,*/*;q=],?Accept-Language,Accept-Encoding=[gzip,deflate],Accept-Charset=[utf-8;q=0.7,*;q=0.7],Keep-Alive=[300],Connection=[keep-alive]::Firefox/

label = s:!:Firefox:3.x
sys   = Windows,@unix
sig   = *:Host,User-Agent,Accept=[,*/*;q=],?Accept-Language,Accept-Encoding=[gzip,deflate],Accept-Charset=[utf-8;q=0.7,*;q=0.7],Keep-Alive=[115],Connection=[keep-alive],?Referer::Firefox/

label = s:!:Firefox:4.x
sys   = Windows,@unix
sig   = *:Host,User-Agent,Accept=[,*/*;q=],?Accept-Language,Accept-Encoding=[gzip, deflate],Accept-Charset=[utf-8;q=0.7,*;q=0.7],Keep-Alive=[115],Connection=[keep-alive],?Referer::Firefox/

; I have no idea where this 'UTF-8' variant comes from, but it happens on *BSD.
; Likewise, no clue why Referer is in a different place for some users.

label = s:!:Firefox:5.x-9.x
sys   = Windows,@unix
sig   = *:Host,User-Agent,Accept=[,*/*;q=],?Accept-Language,Accept-Encoding=[gzip, deflate],Accept-Charset=[utf-8;q=0.7,*;q=0.7],?DNT=[1],Connection=[keep-alive],?Referer:Keep-Alive:Firefox/
sig   = *:Host,User-Agent,Accept=[,*/*;q=],?Accept-Language,Accept-Encoding=[gzip, deflate],Accept-Charset=[UTF-8,*],?DNT=[1],Connection=[keep-alive],?Referer:Keep-Alive:Firefox/
sig   = *:Host,User-Agent,Accept=[,*/*;q=],?Accept-Language,Accept-Encoding=[gzip, deflate],Accept-Charset=[UTF-8,*],?DNT=[1],?Referer,Connection=[keep-alive]:Keep-Alive:Firefox/
sig   = *:Host,User-Agent,Accept=[,*/*;q=],?Accept-Language,Accept-Encoding=[gzip, deflate],Accept-Charset=[utf-8;q=0.7,*;q=0.7],?DNT=[1],?Referer,Connection=[keep-alive]:Keep-Alive:Firefox/
sig   = *:Host,User-Agent,Accept=[,*/*;q=],?Accept-Language,Accept-Encoding=[gzip, deflate],Accept-Charset=[utf-8;q=0.7,*;q=0.7],?Referer,?DNT=[1],Connection=[keep-alive]:Keep-Alive:Firefox/

label = s:!:Firefox:10.x or newer
sys   = Windows,@unix
sig   = *:Host,User-Agent,Accept=[,*/*;q=],?Accept-Language=[;q=],Accept-Encoding=[gzip, deflate],?DNT=[1],Connection=[keep-alive],?Referer:Accept-Charset,Keep-Alive:Firefox/
sig   = *:Host,User-Agent,Accept=[,*/*;q=],?Accept-Language=[;q=],Accept-Encoding=[gzip, deflate],?DNT=[1],?Referer,Connection=[keep-alive]:Accept-Charset,Keep-Alive:Firefox/

; There is this one weird case where Firefox 10.x is indistinguishable
; from Safari 5.1:

label = s:!:Firefox:10.x or Safari 5.x
sys   = Windows,@unix
sig   = *:Host,User-Agent,Accept=[xml;q=0.9,*/*;q=0.8],Accept-Language,Accept-Encoding=[gzip, deflate],Connection=[keep-alive]:Keep-Alive,Accept-Charset,DNT,Referer:Gecko

; ----
; MSIE
; ----

; MSIE 11 no longer sends the 'MSIE' part in U-A, but we don't consider
; U-A to be a robust signal for fingerprinting, so no dice.

label = s:!:MSIE:8 or newer
sys   = Windows
sig   = 1:Accept=[*/*],?Referer,?Accept-Language,User-Agent,Accept-Encoding=[gzip, deflate],Host,Connection=[Keep-Alive]:Keep-Alive,Accept-Charset,UA-CPU:Trident/
sig   = 1:Accept=[*/*],?Referer,?Accept-Language,Accept-Encoding=[gzip, deflate],User-Agent,Host,Connection=[Keep-Alive]:Keep-Alive,Accept-Charset:(compatible; MSIE

label = s:!:MSIE:7
sys   = Windows
sig   = 1:Accept=[*/*],?Referer,?Accept-Language,UA-CPU,User-Agent,Accept-Encoding=[gzip, deflate],Host,Connection=[Keep-Alive]:Keep-Alive,Accept-Charset:(compatible; MSIE

; TODO: Check if this one ever uses Accept-Language, etc. Also try to find MSIE 5.

label = s:!:MSIE:6
sys   = Windows
sig   = 0:Accept=[*/*],?Referer,User-Agent,Host:Keep-Alive,Connection,Accept-Encoding,Accept-Language,Accept-Charset:(compatible; MSIE
sig   = 1:Accept=[*/*],Connection=[Keep-Alive],Host,?Pragma=[no-cache],?Range,?Referer,User-Agent:Keep-Alive,Accept-Encoding,Accept-Language,Accept-Charset:(compatible; MSIE

; ------
; Chrome
; ------

label = s:!:Chrome:11.x to 26.x
sys   = Windows,@unix
sig   = 1:Host,Connection=[keep-alive],User-Agent,Accept=[*/*],?Referer,Accept-Encoding=[gzip,deflate,sdch],Accept-Language,Accept-Charset=[utf-8;q=0.7,*;q=0.3]:: Chrom
sig   = 1:Host,Connection=[keep-alive],User-Agent,Accept=[*/*],?Referer,Accept-Encoding=[gzip,deflate,sdch],Accept-Language,Accept-Charset=[UTF-8,*;q=0.5]:: Chrom
sig   = 1:Host,User-Agent,Accept=[*/*],?Referer,Accept-Encoding=[gzip,deflate,sdch],Accept-Language,Accept-Charset=[utf-8;q=0.7,*;q=0.3],Connection=[keep-alive]::Chrom

label = s:!:Chrome:27.x or newer
sys   = Windows,@unix
sig   = 1:Host,Connection=[keep-alive],Accept=[*/*],User-Agent,?Referer,Accept-Encoding=[gzip,deflate,sdch],Accept-Language:Accept-Charset,Keep-Alive: Chrom

; -----
; Opera
; -----

label = s:!:Opera:19.x or newer
sys   = Windows,@unix
sig   = 1:Host,Connection=[keep-alive],Accept=[*/*;q=0.8],User-Agent,Accept-Encoding=[gzip,deflate,lzma,sdch],Accept-Language=[;q=0.]:Accept-Charset,Keep-Alive:OPR/

label = s:!:Opera:15.x-18.x
sys   = Windows,@unix
sig   = 1:Host,Connection=[keep-alive],Accept=[*/*;q=0.8],User-Agent,Accept-Encoding=[gzip, deflate],Accept-Language=[;q=0.]:Accept-Charset,Keep-Alive:OPR/

label = s:!:Opera:11.x-14.x
sys   = Windows,@unix
sig   = 1:User-Agent,Host,Accept=[*/*;q=0.1],?Accept-Language=[;q=0.],Accept-Encoding=[gzip, deflate],Connection=[Keep-Alive]:Accept-Charset,X-OperaMini-Phone-UA:) Presto/

label = s:!:Opera:10.x
sys   = Windows,@unix
sig   = 1:User-Agent,Host,Accept=[*/*;q=0.1],Accept-Language=[;q=0.],Accept-Charset=[utf-8, utf-16, *;q=0.1],Accept-Encoding=[deflate, gzip, x-gzip, identity, *;q=0],Connection=[Keep-Alive]::Presto/
sig   = 1:User-Agent,Host,Accept=[*/*;q=0.1],Accept-Language=[en],Accept-Encoding=[gzip, deflate],Connection=[Keep-Alive]:Accept-Charset:Opera/

label = s:!:Opera:Mini
sys   = Linux
sig   = 1:User-Agent,Host,Accept=[*/*;q=0.1],Accept-Language=[;q=0.],Accept-Encoding=[gzip, deflate],Connection=[Keep-Alive],X-OperaMini-Phone-UA,X-OperaMini-Features,X-OperaMini-Phone,x-forwarded-for:Accept-Charset:Opera Mini/

label = s:!:Opera:on Nintendo Wii
sys   = Nintendo
sig   = 1:User-Agent,Host,Accept=[*/*;q=0.1],Accept-Language=[en],Accept-Charset=[iso-8859-1, utf-8, utf-16, *;q=0.1],Accept-Encoding=[deflate, gzip, x-gzip, identity, *;q=0],Connection=[Keep-Alive]::Nintendo

; ---------------
; Android browser
; ---------------

label = s:!:Android:2.x
sys   = Linux
sig   = 1:Host,Accept-Encoding=[gzip],Accept-Language,User-Agent,Accept=[,*/*;q=0.5],Accept-Charset=[utf-16, *;q=0.7]:Connection:Android
sig   = 1:Host,Connection=[keep-alive],Accept-Encoding=[gzip],Accept-Language,User-Agent,Accept=[,*/*;q=0.5],Accept-Charset=[utf-16, *;q=0.7]::Android
sig   = 1:Host,Accept-Encoding=[gzip],Accept-Language=[en-US],Accept=[*/*;q=0.5],User-Agent,Accept-Charset=[utf-16, *;q=0.7]:Connection:Android

label = s:!:Android:4.x
sys   = Linux
sig   = 1:Host,Connection=[keep-alive],Accept=[,*/*;q=0.8],User-Agent,Accept-Encoding=[gzip,deflate],Accept-Language,Accept-Charset=[utf-16, *;q=0.7]::Android

; ------
; Safari
; ------

label = s:!:Safari:7 or newer
sys   = @unix
sig   = *:Host,Accept-Encoding=[gzip, deflate],Connection=[keep-alive],Accept=[*/*],User-Agent,Accept-Language,?Referer,?DNT:Accept-Charset,Keep-Alive:KHTML, like Gecko)

label = s:!:Safari:5.1-6
sys   = Windows,@unix
sig   = *:Host,User-Agent,Accept=[*/*],?Referer,Accept-Language,Accept-Encoding=[gzip, deflate],Connection=[keep-alive]:Accept-Charset:KHTML, like Gecko)
sig   = *:Host,User-Agent,Accept=[*/*],?Referer,Accept-Encoding=[gzip, deflate],Accept-Language,Connection=[keep-alive]:Accept-Charset:KHTML, like Gecko)

label = s:!:Safari:5.0 or earlier
sys   = Mac OS X
sig   = 0:Host,User-Agent,Connection=[close]:Accept,Accept-Encoding,Accept-Language,Accept-Charset:CFNetwork/

; ---------
; Konqueror
; ---------

label = s:!:Konqueror:4.6 or earlier
sys   = Linux,FreeBSD,OpenBSD
sig   = 1:Host,Connection=[Keep-Alive],User-Agent,?Pragma,?Cache-control,Accept=[*/*],Accept-Encoding=[x-gzip, x-deflate, gzip, deflate],Accept-Charset=[;q=0.5, *;q=0.5],Accept-Language::Konqueror/

label = s:!:Konqueror:4.7 or newer
sys   = Linux,FreeBSD,OpenBSD
sig   = 1:Host,Connection=[keep-alive],User-Agent,Accept=[*/*],Accept-Encoding=[gzip, deflate, x-gzip, x-deflate],Accept-Charset=[,*;q=0.5],Accept-Language::Konqueror/

; -------------------
; Major search robots
; -------------------

label = s:!:BaiduSpider:
sys   = BaiduSpider
sig   = 1:Host,Connection=[close],User-Agent,Accept=[*/*]:Accept-Encoding,Accept-Language,Accept-Charset:Baiduspider-image
sig   = 1:Host,Accept-Language=[zh-cn],Connection=[close],User-Agent:Accept,Accept-Encoding,Accept-Charset:Baiduspider
sig   = 1:Host,Connection=[close],User-Agent,Accept-Language=[zh-cn,zh-tw],Accept-Encoding=[gzip],Accept=[*/*]:Accept-Charset:Baiduspider
sig   = 1:Host,Connection=[close],User-Agent,Accept-Language=[tr-TR],Accept-Encoding=[gzip],Accept=[*/*]:Accept-Charset:Baiduspider
sig   = 1:Host,Connection=[close],User-Agent,Accept-Encoding=[gzip],?Accept-Language=[zh-cn,zh-tw],Accept=[*/*]:Accept-Charset:Baiduspider
sig   = 1:Host,Connection=[close],User-Agent,Accept-Encoding=[gzip],Accept-Language=[tr-TR],Accept=[*/*]:Accept-Charset:Baiduspider

label = s:!:Googlebot:
sys   = Linux
sig   = 1:Host,Connection=[Keep-alive],Accept=[*/*],From=[googlebot(at)googlebot.com],User-Agent,Accept-Encoding=[gzip,deflate],?If-Modified-Since:Accept-Language,Accept-Charset:Googlebot
sig   = 1:Host,Connection=[Keep-alive],Accept=[text/plain],Accept=[text/html],From=[googlebot(at)googlebot.com],User-Agent,Accept-Encoding=[gzip,deflate]:Accept-Language,Accept-Charset:Googlebot

label = s:!:Googlebot:feed fetcher
sys   = Linux
sig   = 1:Host,Connection=[Keep-alive],Accept=[*/*],User-Agent,Accept-Encoding=[gzip,deflate],?If-Modified-Since:Accept-Language,Accept-Charset:-Google
sig   = 1:User-Agent,?X-shindig-dos=[on],Cache-Control,Host,?X-Forwarded-For,Accept-Encoding=[gzip],?Accept-Language:Connection,Accept,Accept-Charset:Feedfetcher-Google

label = s:!:Bingbot:
sys   = Windows
sig   = 1:Cache-Control,Connection=[Keep-Alive],Pragma=[no-cache],Accept=[*/*],Accept-Encoding,Host,User-Agent:Accept-Language,Accept-Charset:bingbot/

; MSNbot has a really silly Accept header, only a tiny part of which is preserved here:

label = s:!:MSNbot:
sys   = Windows
sig   = 1:Connection=[Close],Accept,Accept-Encoding=[gzip, deflate],From=[msnbot(at)microsoft.com],Host,User-Agent:Accept-Language,Accept-Charset:msnbot

label = s:!:Yandex:crawler
sys   = FreeBSD
sig   = 1:Host,Connection=[Keep-Alive],Accept=[*/*],Accept-Encoding=[gzip,deflate],Accept-Language=[en-us, en;q=0.7, *;q=0.01],User-Agent,From=[support@search.yandex.ru]:Accept-Charset:YandexBot/
sig   = 1:Host,Connection=[Keep-Alive],Accept=[image/jpeg, image/pjpeg, image/png, image/gif],User-Agent,From=[support@search.yandex.ru]:Accept-Encoding,Accept-Language,Accept-Charset:YandexImages/
sig   = 1:Host,Connection=[Keep-Alive],User-Agent,From=[support@search.yandex.ru]:Accept,Accept-Encoding,Accept-Language,Accept-Charset:YandexBot/

label = s:!:Yahoo:crawler
sys   = Linux
sig   = 0:Host,User-Agent,Accept=[,image/png,*/*;q=0.5],Accept-Language=[en-us,en;q=0.5],Accept-Encoding=[gzip],Accept-Charset=[,utf-8;q=0.7,*;q=0.7]:Connection:Slurp

; -----------------
; Misc other robots
; -----------------

label = s:!:Flipboard:crawler
sys   = Linux
sig   = 1:User-Agent,Accept-Language=[en-us,en;q=0.5],Accept-Charset=[;q=0.7,*;q=0.5],Accept-Encoding=[gzip],Host,Accept=[*; q=.2, */*; q=.2],Connection=[keep-alive]::FlipboardProxy
sig   = 1:Accept-language=[en-us,en;q=0.5],Accept-encoding=[gzip],Accept=[;q=0.9,*/*;q=0.8],User-agent,Host:User-Agent,Connection,Accept-Encoding,Accept-Language,Accept-Charset:FlipboardProxy

label = s:!:Spinn3r:crawler
sys   = Linux
sig   = 1:User-Agent,Accept-Encoding=[gzip],Host,Accept=[*; q=.2, */*; q=.2],Connection=[close]:Accept-Language,Accept-Charset:Spinn3r

label = s:!:Facebook:crawler
sys   = Linux
sig   = 1:User-Agent,Host,Accept=[*/*],Accept-Encoding=[deflate, gzip],Connection=[close]:Accept-Language,Accept-Charset:facebookexternalhit/
sig   = 1:User-Agent,Host,Accept=[*/*],Connection=[close]:Accept-Encoding,Accept-Language,Accept-Charset:facebookexternalhit/

label = s:!:paper.li:crawler
sys   = Linux
sig   = 1:Accept-Language=[en-us,en;q=0.5],Accept=[*/*],User-Agent,Connection=[close],Accept-Encoding=[gzip,identity],?Referer,Host,Accept-Charset=[ISO-8859-1,utf-8;q=0.7,*;q=0.7]::PaperLiBot/

label = s:!:Twitter:crawler
sys   = Linux
sig   = 1:User-Agent=[Twitterbot/],Host,Accept=[*; q=.2, */*; q=.2],Cache-Control,Connection=[keep-alive]:Accept-Encoding,Accept-Language,Accept-Charset:Twitterbot/

label = s:!:linkdex:crawler
sys   = Linux
sig   = 0:Host,Connection=[Keep-Alive],User-Agent,Accept-Encoding=[gzip,deflate]:Accept,Accept-Language,Accept-Charset:linkdex.com/

label = s:!:Yodaobot:
sys   = Linux
sig   = 1:Accept-Encoding=[identity;q=0.5, *;q=0.1],User-Agent,Host:Connection,Accept,Accept-Language,Accept-Charset:YodaoBot/

label = s:!:Tweetmeme:crawler
sys   = Linux
sig   = 1:Host,User-Agent,Accept=[,image/png,*/*;q=0.5],Accept-Language=[en-gb,en;q=0.5],Accept-Charset=[ISO-8859-1,utf-8;q=0.7,*;q=0.7]:Connection,Accept-Encoding:TweetmemeBot/

label = s:!:Archive.org:crawler
sys   = Linux
sig   = 0:User-Agent,Connection=[close],Accept=[application/xml;q=0.9,*/*;q=0.8],Host:Accept-Encoding,Accept-Language,Accept-Charset:archive.org

label = s:!:Yahoo Pipes:
sys   = Linux
sig   = 0:Client-IP,X-Forwarded-For,X-YQL-Depth,User-Agent,Host,Connection=[keep-alive],Via:Accept,Accept-Encoding,Accept-Language,Accept-Charset:Yahoo Pipes
sig   = 1:Client-IP,X-Forwarded-For,X-YQL-Depth,User-Agent,Host,Via:Connection,Accept,Accept-Encoding,Accept-Language,Accept-Charset:Yahoo Pipes

label = s:!:Google Web Preview:
sys   = Linux
sig   = 1:Referer,User-Agent,Accept-Encoding=[gzip,deflate],Host,X-Forwarded-For:Connection,Accept,Accept-Language,Accept-Charset:Web Preview

; --------------------------------
; Command-line tools and libraries
; --------------------------------

label = s:!:wget:
sys   = @unix,Windows
sig   = *:User-Agent,Accept=[*/*],Host,Connection=[Keep-Alive]:Accept-Encoding,Accept-Language,Accept-Charset:Wget/

label = s:!:Lynx:
sys   = @unix,Windows
sig   = 0:Host,Accept=[text/sgml, */*;q=0.01],Accept-Encoding=[gzip, compress],Accept-Language,User-Agent:Connection,Accept-Charset:Lynx/

label = s:!:curl:
sys   = @unix,Windows
sig   = 1:User-Agent,Host,Accept=[*/*]:Connection,Accept-Encoding,Accept-Language,Accept-Charset:curl/

label = s:!:links:
sys   = @unix,Windows
sig   = 1:Host,User-Agent,Accept=[*/*],Accept-Encoding=[gzip, deflate, bzip2],Accept-Charset=[us-ascii],Accept-Language=[;q=0.1],Connection=[Keep-Alive]::Links
sig   = 1:Host,User-Agent,Accept=[*/*],Accept-Encoding=[gzip,deflate,bzip2],Accept-Charset=[us-ascii],Accept-Language=[;q=0.1],Connection=[keep-alive]::Links

label = s:!:elinks:
sys   = @unix,Windows
sig   = 1:Host,User-Agent,Accept=[*/*],Accept-Encoding=[bzip2, deflate, gzip],Accept-Language:Connection,Accept-Charset:ELinks/

label = s:!:Java:JRE
sys   = @unix,@win
sig   = 1:User-Agent,Host,Accept=[*; q=.2, */*; q=.2],Connection=[keep-alive]:Accept-Encoding,Accept-Language,Accept-Charset:Java/

label = s:!:Python:urllib
sys   = @unix,Windows
sig   = 1:Accept-Encoding=[identity],Host,Connection=[close],User-Agent:Accept,Accept-Language,Accept-Charset:Python-urllib/

label = s:!:w3m:
sys   = @unix,Windows
sig   = 0:User-Agent,Accept=[image/*],Accept-Encoding=[gzip, compress, bzip, bzip2, deflate],Accept-Language=[;q=1.0],Host:Connection,Accept-Charset:w3m/

label = s:!:libfetch:
sys   = @unix
sig   = 1:Host,User-Agent,Connection=[close]:Accept,Accept-Encoding,Accept-Language,Accept-Charset:libfetch/

; -------------
; Odds and ends
; -------------

label = s:!:Google AppEngine:
sys   = Linux
sig   = 1:User-Agent,Host,Accept-Encoding=[gzip]:Connection,Accept,Accept-Language,Accept-Charset:AppEngine-Google

label = s:!:WebOS:
sys   = Linux
sig   = 1:Host,Accept-Encoding=[gzip, deflate],User-Agent,Accept=[,*/*;q=0.5],Accept-Language,Accept-Charset=[utf-8;q=0.7,*;q=0.3]:Connection:wOSBrowser

label = s:!:xxxterm:
sys   = @unix
sig   = 1:Host,User-Agent,Accept=[*/*],Accept-Encoding=[gzip]:Connection,Accept-Language,Accept-Charset:xxxterm

label = s:!:Google Desktop:
sys   = Windows
sig   = 1:Accept=[*/*],Accept-Encoding=[gzip],User-Agent,Host,Connection=[Keep-Alive]:Accept-Language,Accept-Charset:Google Desktop/

label = s:!:luakit:
sys   = @unix
sig   = 1:Host,User-Agent,Accept=[*/*],Accept-Encoding=[gzip],Connection=[Keep-Alive]:Accept-Language,Accept-Charset:luakit

label = s:!:Epiphany:
sys   = @unix
sig   = 1:Host,User-Agent,Accept=[*/*],Accept-Encoding=[gzip],Accept-Language:Connection,Accept-Charset,Keep-Alive:Epiphany/

; =====================
; SSL client signatures
; =====================

[ssl:request]

;-----------------
; Windows specific
;-----------------

; Windows NT 5.1, Windows NT 5.2 (XP)
label = s:!:any:MSIE or Safari on Windows XP
sys   = Windows
sig   = 3.1:4,5,a,9,64,62,3,6,13,12,63:ff01:
; no MS10-049 applied?
sig   = 3.1:4,5,a,9,64,62,3,6,13,12,63::

; with some SSL/TLS options tweaked
sig   = 3.0:4,5,a,9,64,62,3,6,13,12,63,ff::
sig   = 3.0:4,5,a,10080,700c0,30080,9,60040,64,62,3,6,20080,40080,13,12,63,ff::v2
sig   = 2.0:10080,700c0,30080,60040,20080,40080,ff::v2


; Windows NT 6.0 (Vista)
label = s:!:any:MSIE 5.5-6 or Chrome 1-4 or Safari on Windows Vista
sys   = Windows
sig   = 3.1:2f,35,5,a,c009,c00a,c013,c014,32,38,13,4:?0,a,b,ff01:

label = s:!:any:MSIE 7.0-9.0 or Chrome 5 on Windows Vista
sys   = Windows
sig   = 3.1:2f,35,5,a,c009,c00a,c013,c014,32,38,13,4:?0,5,a,b,ff01:


; Windows NT 6.1 (7)
label = s:!:MSIE:7-9 on Windows 7
sys   = Windows
sig   = 3.1:2f,35,5,a,c013,c014,c009,c00a,32,38,13,4:ff01,?0,5,a,b:

label = s:!:Safari:on Windows 7
sys   = Windows
sig   = 3.1:2f,35,5,a,c013,c014,c009,c00a,32,38,13,4:ff01,?0,a,b:

; Windows NT 6.2 ( 8)
; 23 usually means NT 6.2
label = s:!:MSIE:10 on Windows 8
sys   = Windows
sig   = 3.1:2f,35,5,a,c013,c014,c009,c00a,32,38,13,4:ff01,?0,5,a,b,23:

label = s:!:Safari:Safari on Windows 8
sys   = Windows
sig   = 3.1:2f,35,5,a,c013,c014,c009,c00a,32,38,13,4:ff01,?0,a,b,23:


; ------
; Chrome
; ------

label = s:!:Chrome:6 or newer
sys   = Windows,@unix
sig   = 3.1:c00a,c014,88,87,39,38,c00f,*,c003,feff,a:?0,ff01,a,b,23:compr
sig   = 3.1:c00a,c014,88,87,39,38,c00f,*,c003,feff,a:?0,ff01,a,b,23,3374:compr
; 5 is on on windows
sig   = 3.1:c00a,c014,88,87,39,38,c00f,*,c003,feff,a:?0,ff01,a,b,23,3374,5:compr

label = s:!:Chrome:degraded to SSLv3.0
sys   = Windows,@unix
sig   = 3.0:ff,88,87,39,38,84,35,45,44,66,33,32,96,41,4,5,2f,16,13,feff,a::

; -------
; Firefox
; -------

label = s:!:Firefox:1.X
sys   = Windows,@unix
sig   = 3.1:10080,30080,*,40080,39,38,35,*,64,62,3,6::v2
sig   = 3.1:39,38,35,*,64,62,3,6::stime

label = s:!:Firefox:2.X
sys   = Windows,@unix
sig   = 3.1:c00a,c014,39,38,c00f,*,c00d,c003,feff,a:?0,a,b:

label = s:!:Firefox:3.0-3.5
sys   = Windows,@unix
sig   = 3.1:c00a,c014,88,87,39,38,c00f,c005,84,35,c007,*,c003,feff,a:?0,a,b,23:

label = s:!:Firefox:3.6.X
sys   = Windows,@unix
sig   = 3.1:ff,c00a,c014,88,87,38,c00f,c005,84,35,39,*,c00d,c003,feff,a:?0,a,b,23:

label = s:!:Firefox:4-11
sys   = Windows,@unix
sig   = 3.1:ff,c00a,c014,88,87,39,38,*,c003,feff,a:?0,a,b,23:
; with SSLv2 disalbed
sig   = 3.1:c00a,c014,88,87,39,38,*,c003,feff,a:?0,ff01,a,b,23:

label = s:!:Firefox:11 (TOR)
sys   = Windows,@unix
; Lack of a single extension (SessionTicket TLS) is not a very strong signal.
sig   = 3.1:ff,c00a,c014,88,87,39,38,*,c003,feff,a:?0,a,b:

label = s:!:Firefox:14 or newer
sys   = Windows,@unix
sig   = 3.1:ff,c00a,c014,88,87,39,38,*,c003,feff,a:?0,a,b,23,3374:

; with TLS switched off
label = s:!:Firefox:3.6.X or newer
sys   = Windows,@unix
sig   = 3.0:ff,88,87,39,38,84,35,45,44,33,32,96,41,4,5,2f,16,13,feff,a::


; ------
; Safari
; ------
; Safari on old PowerPC box
label = s:!:Safari:4.X
sys   = Mac OS X
sig   = 3.1:2f,5,4,35,a,ff83,*,17,19,1::
sig   = 3.1:2f,5,4,35,a,ff83,*,17,19,1,10080,*,700c0::v2

label = s:!:Safari:5.1.2
sys   = Mac OS X
sig   = 3.1:c00a,c009,c007,c008,c013,*,33,38,39,16,15,14,13,12,11:?0,a,b:

label = s:!:Safari:5.1.3 or newer
sys   = Mac OS X
sig   = 3.1:c00a,c009,c007,c008,c013,*,33,38,39,16,13:?0,a,b:


; -------
; Android
; -------

; in http Android is treated as Linux, oh, well...
label = s:!:Android:1.5-2.1
sys   = Linux
sig   = 3.1:39,38,35,16,13,a,33,32,2f,5,4,15,12,9,14,11,8,6,3::

label = s:!:Android:2.3
sys   = Linux
sig   = 3.1:4,5,2f,33,32,a,16,13,9,15,12,3,8,14,11,ff::

label = s:!:Android:3.2
sys   = Linux
sig   = 3.1:c014,c00a,39,38,c00f,c005,35,*,c00c,c002,5,4,15,12,9,14,11,8,6,3,ff:?0,b,a,23,3374:compr

label = s:!:Android:4.X
sys   = Linux
sig   = 3.1:c014,c00a,39,38,c00f,c005,35,*,c00c,c002,5,4,ff:?0,b,a,23,3374:compr

; -----------
; iPhone iPad
; -----------

label = s:!:Safari:iOS 4.X
sys   = iOS
sig   = 3.1:c00a,c009,c007,*,33,39,16,15,14:?0,a,b:

label = s:!:Safari:iOS 5.X
sys   = iOS
sig   = 3.3:ff,c024,c023,c00a,*,33,39,16:?0,a,b,d:


; ------------
; Weird Mobile
; ------------
label = s:!:Opera Mini:11.X
sys   = Windows,@unix
sig   = 3.1:39,38,37,36,35,33,32,31,30,2f,5,4,13,d,16,10,a:?0,ff01,5:
sig   = 3.1:ff,39,38,37,36,35,33,32,31,30,2f,5,4,13,d,16,10,a:?0,ff01,5:

label = s:!:HP-tablet:unknown
sys   = Touchpad
sig   = 3.1:39,38,35,16,13,a,33,32,2f,5,4:?0:


; -----
; Opera
; -----

label = s:!:Opera:10.x - 11.00
sys   = Windows,@unix
sig   = 3.2:6b,6a,69,68,3d,39,38,37,36,35,67,40,3f,3e,3c,33,32,31,30,2f,5,4,13,d,16,10,a:?0,5:ver
sig   = 3.3:6b,6a,69,68,3d,39,38,37,36,35,67,40,3f,3e,3c,33,32,31,30,2f,5,4,13,d,16,10,a:?0,ff01,5,d:ver

label = s:!:Opera:11.52 or newer
sys   = Windows,@unix
sig   = 3.1:6b,6a,69,68,3d,39,38,37,36,35,67,40,3f,3e,3c,33,32,31,30,2f,5,4,13,d,16,10,a:?0,ff01,5:
sig   = 3.1:ff,6b,6a,69,68,3d,39,38,37,36,35,67,40,3f,3e,3c,33,32,31,30,2f,5,4,13,d,16,10,a:?0,ff01,5:

; On second connection Opera replies with the last used crypto in a first place I guess
label = s:!:Opera:
sys   = Windows,@unix
sig   = 3.1:*,6b,6a,69,68,3d,*,13,d,16,10,a:?0,?ff01,5:
sig   = 3.1:*,39,38,37,36,35,*,13,d,16,10,a:?0,?ff01,5:
sig   = 3.2:*,6b,6a,69,68,3d,*,13,d,16,10,a:?0,?ff01,5:
sig   = 3.2:*,39,38,37,36,35,*,13,d,16,10,a:?0,?ff01,5:
sig   = 3.3:*,6b,6a,69,68,3d,*,13,d,16,10,a:?0,?ff01,5:
sig   = 3.3:*,39,38,37,36,35,*,13,d,16,10,a:?0,?ff01,5:


; --------------
; Various things
; --------------

label = g:!:gnutls:
sys   = @unix
sig   = 3.1:33,16,39,2f,a,35,5,4,32,13,38,66::compr
sig   = 3.2:2f,5,4,a,35,32,66,13,38,33,16,39,34,18,1b,3a,3::
sig   = 3.3:3c,2f,5,4,a,3d,35,40,32,66,13,6a,38,67,33,16,6b,39,6c,34,18,1b,6d,3a:ff01,d:
sig   = 3.1:*,2f,5,4,a,*,35,*,18,1b,3a,*:*:


label = g:!:openssl:
sys   = @unix
sig   = 3.1:39,38,35,16,13,a,33,32,2f,5,4,15,12,9,14,11,8,6,3,ff:23:compr
sig   = 3.1:39,38,35,16,13,a,33,32,2f,5,4,15,12,9,14,11,8,6,3,ff:?0:compr
sig   = 3.1:39,38,35,16,13,a,33,32,2f,5,4,15,12,9,14,11,8,6,3,ff:?0,23:
sig   = 3.1:39,38,35,16,13,a,33,32,2f,9a,99,96,5,4,15,12,9,14,11,8,6,3,ff:?0,23:compr
sig   = 3.1:39,38,35,16,13,a,33,32,2f,9a,99,96,5,4,15,12,9,14,11,8,6,3,ff:?0:compr

; darwin
sig   = 3.1:39,38,35,16,13,a,700c0,33,32,2f,9a,99,96,30080,5,4,10080,15,12,9,60040,14,11,8,6,40080,3,20080,ff::v2
sig   = 3.1:39,38,35,16,13,a,700c0,33,32,2f,30080,5,4,10080,15,12,9,60040,14,11,8,6,40080,3,20080,ff::v2

sig   = 3.1:39,38,88,87,35,84,16,13,a,33,32,9a,99,45,44,2f,96,41,5,4,15,12,9,14,11,8,6,3,ff:23:compr
sig   = 3.1:c014,c00a,39,38,88,87,c00f,c005,35,84,*,8,6,3,ff:b,a,23:compr
sig   = 3.1:c014,c00a,39,38,88,87,c00f,c005,35,84,*,8,6,3,ff:?0,b,a:compr

label = s:!:Epiphany:2.X
sys   = Linux
sig   = 3.0:33,39,16,32,38,13,2f,35,a,5,4::
