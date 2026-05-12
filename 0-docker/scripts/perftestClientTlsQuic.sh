#!/bin/sh

set -e

#if [ "x$TC_DELAY" == "x" ]; then
if [ -z "$TC_DELAY" ]; then
    TC_DELAY=0ms
fi    

#if [ "x$TC_LOSS" == "x" ]; then
if [ -z "$TC_LOSS" ]; then
    TC_LOSS="0%"
fi 

if [ -z "$DOCKER_HOST" ]; then
    DOCKER_HOST="localhost"
fi 

if [ -z "$USE_TLS" ]; then
    USE_TLS="true"
fi 

if [ -z "$NUM_RUNS" ]; then
    NUM_RUNS=500
fi 

if [ -z "$CERT_PATH" ]; then
    export CERT_PATH=/cert
fi

if [ -z "$MUTUAL" ]; then
     MUTUAL="true"
fi

INTERFAZ="eth0"

echo "Applying netem rules to $INTERFAZ..."
tc qdisc add dev "$INTERFAZ" root netem delay $TC_DELAY loss $TC_LOSS 2>/dev/null || true

echo "Showing qdisc status for the interface: $INTERFAZ"
tc -s qdisc show dev "$INTERFAZ" 2>/dev/null || true


# ---------------------------
# Set KEM and Signature algorithm
# ---------------------------
# Optionally set KEM to one defined in https://github.com/open-quantum-safe/oqs-provider#algorithms
#if [ "x$KEM_ALG" == "x" ]; then
if [ -z "$KEM_ALG" ]; then
    KEM_ALG=mlkem512
fi
export DEFAULT_GROUPS=$KEM_ALG

# Optionally set SIG to one defined in https://github.com/open-quantum-safe/oqs-provider#algorithms
#if [ "x$SIG_ALG" == "x" ]; then
if [ -z "$SIG_ALG" ]; then
	export SIG_ALG=mldsa44
fi

# Optionally set TEST_TIME
#if [ "x$TEST_TIME" == "x" ]; then
if [ -z "$TEST_TIME" ]; then
	export TEST_TIME=1
fi

# ---------------------------
# Create certificates 
# ---------------------------
# Optionally set server certificate alg to one defined in https://github.com/open-quantum-safe/oqs-provider#algorithms
# The root CA's signature alg remains as set when building the image
#CERT_PATH=/opt/certs

echo "Running $0 with SIG_ALG=$SIG_ALG and KEM_ALG=$KEM_ALG"


# ---------------------------
# Launch TLS OR QUIC client
# ---------------------------
# Start a TLS1.3 test server based on OpenSSL accepting only the specified KEM_ALG
# The env var DEFAULT_GROUPS activates the required Group via the system openssl.cnf:
# we put it on the command line to check for possible typos otherwise silently discarded:

NUM_RUNS=${NUM_RUNS:-500}
TIMEOUT=${TIMEOUT:-600}

i=1
       
    while [ $i -le $NUM_RUNS ]
    do
    if [ "$USE_TLS" = "true" ]; then
     
          if [ "$MUTUAL" = "true" ]; then
            echo "Execution $i - TLS Mutual"
            timeout $TIMEOUT openssl s_connection -connect $DOCKER_HOST:4433 -new  -verify 1 -CAfile $CERT_PATH/CA.crt -cert $CERT_PATH/user.crt  -key $CERT_PATH/user.key 2>/dev/null || echo "Execution $i - TIMEOUT"
          
          else
            echo "Execution $i - TLS Single" 
            timeout $TIMEOUT openssl s_connection -connect $DOCKER_HOST:4433 -new -verify 1 -CAfile $CERT_PATH/CA.crt 2>/dev/null || echo "Execution $i - TIMEOUT"

          fi   
    else

        if [ -n "${SSL_DIR:-}" ]; then
            mkdir -p "$SSL_DIR"
            KEYLOG_PATH="${SSL_DIR}/sslkeys_client_${SIG_ALG}_${KEM_ALG}.log"
            echo "🔐 QUIC keys will be stored in: $KEYLOG_PATH"
            export SSLKEYLOGFILE="$KEYLOG_PATH"
        fi
        
        if [ "$MUTUAL" = "true" ]; then
          echo "Execution $i - QUIC Mutual"
          timeout $TIMEOUT quics_connection -groups:$KEM_ALG -target:$DOCKER_HOST -CAfile:"$CERT_PATH/CA.crt" -cert $CERT_PATH/user.crt  -key $CERT_PATH/user.key 2>/dev/null || echo "Execution $i - TIMEOUT"

        else
          echo "Execution $i - QUIC Single" 
          timeout $TIMEOUT quics_connection -groups:$KEM_ALG -target:$DOCKER_HOST -CAfile:"$CERT_PATH/CA.crt" 2>/dev/null || echo "Execution $i - TIMEOUT"

        fi   
    fi


    i=$((i + 1))
    done
