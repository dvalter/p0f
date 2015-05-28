FROM		debian:jessie

# install dependencies
RUN		apt-get update -qq && \
		apt-get upgrade --yes && \
    		apt-get install -y --no-install-recommends build-essential libpcap0.8 libpcap0.8-dev && \
		apt-get clean autoclean && \
		apt-get autoremove --yes && \ 
		rm -rf /var/lib/{apt,dpkg,cache,log}/

ADD		. /usr/src/p0f

RUN		cd /usr/src/p0f && \
		make && \
		mkdir -p /opt/p0f/bin /opt/p0f/log && \
		cp /usr/src/p0f/p0f /opt/p0f/bin

ADD		./docker-entrypoint.sh /usr/local/sbin/docker-entrypoint.sh

ENTRYPOINT	["/usr/local/sbin/docker-entrypoint.sh"]

CMD		["/opt/p0f/bin/p0f"]
