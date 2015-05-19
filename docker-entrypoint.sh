#!/bin/bash
set -e

FILTER_RULE=${FILTER_RULE:-port 80 or port 443}
FINGERPRINT_DATABASE=${FINGERPRINT_DATABASE:-/opt/p0f/etc/p0f.fp}
CONNECTION_HOST_CACHE_LIMIT=${CONNECTION_HOST_CACHE_LIMIT:-30,120}
CONNECTION_HOST_CAP_LIMIT=${CONNECTION_HOST_CAP_LIMIT:-1000,10000}
UNIX_SOCKET=${UNIX_SOCKET:-/opt/p0f/run/p0f.sock}
PARALLEL_API_CONNECTIONS=${PARALLEL_API_CONNECTIONS:-100}

if [ "$1" == "/usr/bin/supervisord" ]; then
	POF_OPTS=" -f ${FINGERPRINT_DATABASE}"
	POF_OPTS+=" -t ${CONNECTION_HOST_CACHE_LIMIT}"
	POF_OPTS+=" -m ${CONNECTION_HOST_CAP_LIMIT}"

	if [ ! -z "${INTERFACE}" ]; then
		POF_OPTS+=" -i ${INTERFACE}"
	fi

	POF_OPTS+=" -s ${UNIX_SOCKET}"
	POF_OPTS+=" -S ${PARALLEL_API_CONNECTIONS}"

	if [ ! -z "${LOG_FILE}" ]; then
		POF_OPTS+=" -o ${LOG_FILE}"
	fi

	echo "[program:p0f]" >>/etc/supervisor/conf.d/p0f.conf
	echo "command=/opt/p0f/bin/p0f $POF_OPTS '${FILTER_RULE}'" >>/etc/supervisor/conf.d/p0f.conf
	echo "priority=1" >>/etc/supervisor/conf.d/p0f.conf
	echo "autorestart=true" >>/etc/supervisor/conf.d/p0f.conf
	echo "stdout_logfile=/dev/stdout" >>/etc/supervisor/conf.d/p0f.conf
	echo "stdout_logfile_maxbytes=0" >>/etc/supervisor/conf.d/p0f.conf
	echo "stderr_logfile=/dev/stderr" >>/etc/supervisor/conf.d/p0f.conf
	echo "stderr_logfile_maxbytes=0" >>/etc/supervisor/conf.d/p0f.conf
fi

exec "$@"

