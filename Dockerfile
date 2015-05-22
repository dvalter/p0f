FROM		debian:jessie

# install dependencies
RUN		apt-get update -qq && \
		apt-get upgrade --yes && \
    		apt-get install -y --no-install-recommends build-essential libpcap0.8 libpcap0.8-dev apache2 php5 supervisor && \
		apt-get clean autoclean && \
		apt-get autoremove --yes && \ 
		rm -rf /var/lib/{apt,dpkg,cache,log}/

# redirect apache2 logs to stderr / stdout
RUN find /etc/apache2 -type f -exec sed -ri ' \
    s!^(\s*CustomLog)\s+\S+!\1 /proc/self/fd/1!g; \
    s!^(\s*ErrorLog)\s+\S+!\1 /proc/self/fd/2!g; \
    s!^Listen 80!Listen 1337!g; \
    s!^<VirtualHost *:80>!<VirtualHost *:1337>!g; \

' '{}' ';'

ADD		. /usr/src/p0f

RUN		cd /usr/src/p0f && \
		make && \
		mkdir -p /opt/p0f/bin /opt/p0f/etc /opt/p0f/log && \
		cp /usr/src/p0f/p0f /opt/p0f/bin && \
		cp /usr/src/p0f/p0f.fp /opt/p0f/etc && \
		rm /var/www/html/* && \
		cp -aR /usr/src/p0f/php/* /var/www/html/

ADD		./supervisord.conf  /etc/supervisor/conf.d/supervisord.conf
ADD		./docker-entrypoint.sh /usr/local/sbin/docker-entrypoint.sh

ENTRYPOINT	["/usr/local/sbin/docker-entrypoint.sh"]

CMD		["/usr/bin/supervisord"]
