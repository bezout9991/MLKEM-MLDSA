#!/bin/bash

#!/usr/bin/env bash
set -euo pipefail

###############################################################################
#  COMMAND LINE PARAMETERS
#
#  Usage: ./Launcher.sh [tls|quic] [mutual|single] [capture|captureKey|nocapture] [none|simple|stable|unstable] [loss-percent] [delay-ms]
###############################################################################

PROTOCOL=${1:-tls}
AUTH_MODE=${2:-single}
CAPTURE_MODE=${3:-nocapture}
NETWORK_PROFILE=${4:-none}
LOSS_PERC=${5:-0}
DELAY_MS=${6:-0}

USAGE="Usage: $0 [tls|quic] [mutual|single] [capture|captureKey|nocapture] [none|simple|stable|unstable] [loss-percent] [delay-ms]"

NETIF="eth0"
MUTUAL_AUTHENTICATION=false
IMAGE=uma-tls-quic-pq-34
os=""
###############################################################################
#  Input Validation
###############################################################################

# 1) Protocol
if [[ "$PROTOCOL" != "tls" && "$PROTOCOL" != "quic" ]]; then
    echo "$USAGE"
    exit 1
fi

# 2) Mutual authentication mode
if [[ "$AUTH_MODE" != "mutual" && "$AUTH_MODE" != "single" ]]; then
    echo "Invalid authentication mode: must be 'mutual' or 'single'."
    echo "$USAGE"
    exit 1
fi

# 3) Packet capture mode
if [[ "$CAPTURE_MODE" != "capture" && "$CAPTURE_MODE" != "captureKey" && "$CAPTURE_MODE" != "nocapture" ]]; then
    echo "Invalid capture mode: must be 'capture', 'captureKey', or 'nocapture'."
    echo "$USAGE"
    exit 1
fi

# 4) Network profile
if [[ "$NETWORK_PROFILE" != "none" && "$NETWORK_PROFILE" != "simple" && "$NETWORK_PROFILE" != "stable" && "$NETWORK_PROFILE" != "unstable" ]]; then
    echo "Invalid network profile: must be 'none', 'simple', 'stable', or 'unstable'."
    echo "$USAGE"
    exit 1
fi

# 5) Packet loss percentage (0–100)
if ! [[ "$LOSS_PERC" =~ ^[0-9]+$ ]] || (( LOSS_PERC < 0 || LOSS_PERC > 100 )); then
    echo "Invalid loss-percent: must be an integer between 0 and 100."
    echo "$USAGE"
    exit 1
fi

# 6) Delay in milliseconds (>= 0)
if ! [[ "$DELAY_MS" =~ ^[0-9]+$ ]] || (( DELAY_MS < 0 )); then
    echo "Invalid delay-ms: must be a non-negative integer."
    echo "$USAGE"
    exit 1
fi



###############################################################################
#  CONFIGURATION
###############################################################################

 NUM_RUNS=500

if [[ "$CAPTURE_MODE" == "capture" || "$CAPTURE_MODE" == "captureKey" ]]; then
  NUM_RUNS=1
fi

if [[ "$AUTH_MODE" == "mutual" ]]; then
   MUTUAL_AUTHENTICATION=true  
fi

 OQS_SERVER="serveur"
 OQS_CLIENT="client"
 SUPPORTED_SIG_ALGS=("ed25519" "secp384r1" "secp521r1")
 KEMS_L1=("P-256" "x25519" "p256_mlkem512" "x25519_mlkem512" "mlkem512")
 KEMS_L3=("P-384" "x448" "p384_mlkem768" "x448_mlkem768" "mlkem768")
 KEMS_L5=("P-521" "p521_mlkem1024" "mlkem1024")
# Recoger el parámetro de línea de comandos
 USE_TLS=$([[ "$PROTOCOL" == "tls" ]] && echo true || echo false)
 # Perfiles GE-model (valores en %)
STABLE_GEMODEL=(10 50 70 10)    # pg10 pb50 h70 k10
UNSTABLE_GEMODEL=(20 40 90 20)  # pg20 pb40 h90 k20


echo "*************************************"
echo "Parameters valid. Starting with:"
echo "  Protocol:        $PROTOCOL"
echo "  Auth Mode:       $AUTH_MODE"
echo "  Capture Mode:    $CAPTURE_MODE"
echo "  Network Profile: $NETWORK_PROFILE"
echo "  Loss %:          $LOSS_PERC"
echo "  Delay (ms):      $DELAY_MS"
echo "  Executions:      $NUM_RUNS"

echo "  Signature:       ${SUPPORTED_SIG_ALGS[*]}"
echo "  KEMS Level 1:    ${KEMS_L1[*]}"
echo "  KEMS Level 3:    ${KEMS_L3[*]}"
echo "  KEMS Level 5:    ${KEMS_L5[*]}"
echo "*************************************"

###############################################################################
#  Function: detect_platform
#    
###############################################################################

detect_platform() {
    os="$(uname -s)"
    case "$os" in
        Linux)
            echo "Runnig on Linux" ;;
        Darwin)
            echo "Runnig on macOS" ;;
        *)
            echo "Runnig on: $os" ;;
    esac
}

###############################################################################
#  Function: launch_edgeshark
#    
###############################################################################
launch_edgeshark() {
    # 1) Variables
    URL="https://github.com/siemens/edgeshark/raw/main/deployments/wget/docker-compose-localhost.yaml"
    COMPOSE_FILE="./docker-compose-localhost.yaml"  # ruta fija

    # 2) Descargar (si ha cambiado) el fichero de Compose
    mkdir -p "$(dirname "$COMPOSE_FILE")"
    wget -q --no-cache -O "$COMPOSE_FILE" "$URL"

    # 3) Comprobar si hay contenedores levantados
    #    --quiet -q return  IDs; if it is empty, there is no runnig container
    if [ -z "$(docker compose -f "$COMPOSE_FILE" ps -q)" ]; then
        echo "$(date '+%F %T') → No active containers. Running stack..." 
        docker compose -f "$COMPOSE_FILE" up -d 
    else
        echo "$(date '+%F %T') → It is runnig. Nothing to do." 
    fi
}
###############################################################################
#  Function: lauch_Wireshark
#    
###############################################################################

lauch_Wireshark_mac(){

     if [ -d "/Applications/Wireshark.app" ]; then
                    echo "Wireshark is installed, perfect!!!"

                    if ps aux | grep -i wireshark | grep -v grep > /dev/null; then         
                        echo "Wireshark is running."
                        # Espera a que el usuario esté listo
                        read -n 1 -s -r -p "Please save Wireshark data to run another experiment..."
                        echo ""
                        echo "Running now ... "
                        open -a Wireshark

                    else
                        echo "Wireshark is NOT running. Running now ... "
                        open -a Wireshark
                    fi 
            else
                echo "Wireshark is not installed in /Applications."
                exit 1
            fi

            # Espera a que el usuario esté listo
            read -n 1 -s -r -p "Configure Wireshark and press any key when you are ready to continue..."
            echo ""
}

###############################################################################
#  Function: lauch_Wireshark
#    
###############################################################################

launch_wireshark_linux() {
    # Check if the 'wireshark' command is available
    if command -v wireshark >/dev/null 2>&1; then
        echo "Wireshark is installed, perfect!!!"

        # Check if Wireshark is already running (as the current user)
        if pgrep -u "$USER" -x wireshark >/dev/null 2>&1; then
            echo "Wireshark is already running."
        else
            echo "Wireshark is NOT running. Starting now..."
            # Launch Wireshark in the background
            wireshark 
            # Give it a moment to start
            sleep 1
        fi

        # Wait for the user to save or inspect captures before proceeding
        read -n 1 -s -r -p "Please save Wireshark data to run another experiment, then press any key to continue..."
        echo ""
        read -n 1 -s -r -p "Configure Wireshark and press any key when you are ready to continue..."
        echo ""

    else
        echo "Wireshark is not installed. Please install it (e.g. Ubuntu/Debian: sudo apt install wireshark) and try again."
        exit 1
    fi
}
###############################################################################
#  Function: cleaning
#    
###############################################################################

cleaning(){
    docker kill $OQS_SERVER &>/dev/null || true
    docker kill $OQS_CLIENT &>/dev/null || true

    sleep 1
    docker container prune -f
    docker volume rm cert || true
    docker network rm localNet || true
    sleep 1
}

detect_platform

cleaning

echo ""
echo "*************************************"
echo "***NETWORK AND VOLUMEN **************"
echo "*************************************"

# Crear red si no existe
if ! docker network inspect localNet >/dev/null 2>&1; then
    docker network create localNet
    echo "✅ Red localNet created."
else
    echo "ℹ️  Red localNet already exists; it won’t be created."
fi

# Crear volumen si no existe
if ! docker volume inspect cert >/dev/null 2>&1; then
    docker volume create cert
    echo "✅ Volumen cert created."
else
    echo "ℹ️  Volumen cert already exists; it won’t be created."
fi

echo "*************************************"



if [[ "$CAPTURE_MODE" == "capture" || "$CAPTURE_MODE" == "captureKey" ]]; then
    echo ""
    echo "Launching edgeshark"
    launch_edgeshark
 fi   

# Lista de firmas y sus KEMs
SIG_ALGS=("${SUPPORTED_SIG_ALGS[@]}")


for SIG_ALG in "${SIG_ALGS[@]}"; do
    echo ""
    echo " ==> Executing for SIG_ALG: $SIG_ALG"

    if [ "$SIG_ALG" = "ed25519" ]; then
        KEMS=("${KEMS_L1[@]}")
    elif [ "$SIG_ALG" = "secp384r1" ]; then
        KEMS=("${KEMS_L3[@]}")
    elif [ "$SIG_ALG" = "secp521r1" ]; then
        KEMS=("${KEMS_L5[@]}")
    fi

    echo ""
    echo " ==> Creating Certs and Keys"
    docker run --rm -v cert:/cert -e CERT_PATH=/cert/ -e SIG_ALG=$SIG_ALG -it "$IMAGE" doCert.sh

    
    for KEM in "${KEMS[@]}"; do
        echo ""
        echo "****************"
        echo "  -> KEM: $KEM"


        
            echo ""
            echo "    Executing docker Server..."

            docker rm -f $OQS_SERVER $OQS_CLIENT 2>/dev/null

            SSL_DIR="$HOME/captures/sslkeys"

            if [ "$PROTOCOL" = "tls" ] && [ "$CAPTURE_MODE" = "captureKey" ]; then
                mkdir -p "$SSL_DIR"

                SSLKEY_NAME="sslkeys_server_${SIG_ALG}_${KEM}.log"
                SSLKEY_PATH="$SSL_DIR/$SSLKEY_NAME"

                echo "[INFO] TLS Capture mode server: saving SSL keys to $SSLKEY_PATH"
                export SSLKEYLOGFILE="$SSLKEY_PATH"
            fi
    

            docker run --cap-add=NET_ADMIN  \
              --name $OQS_SERVER  \
              --network localNet  \
              -v cert:/cert   \
              -v "$SSL_DIR":/sslkeys \
              -e TC_DELAY=0ms  \
              -e TC_LOSS=0% \
              -e CERT_PATH=/cert/ \
              -e KEM_ALG=$KEM  \
              -e SIG_ALG=$SIG_ALG \
              -e USE_TLS=$USE_TLS \
              -e MUTUAL=$MUTUAL_AUTHENTICATION \
             $( [ "$PROTOCOL" = "tls" ] && [ "$CAPTURE_MODE" = "captureKey" ] && echo "-e SSL_DIR=/sslkeys" ) \
              -d $IMAGE perftestServerTlsQuic.sh
           
            sleep 3    

            echo "    Buscando IP.. "
            IP=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$OQS_SERVER")
            echo "    IP..  $IP"

            
            if [[ "$CAPTURE_MODE" == "capture" || "$CAPTURE_MODE" == "captureKey" ]]; then
                echo ""
                echo "Launching Wireshark"

                if [[ "$os" == "Darwin" ]]; then
                    lauch_Wireshark_mac
                else
                    launch_wireshark_linux
                fi    
            fi   


            ############################################################################
            #  NETWORK IMPAIRMENTS (Pumba)
            ############################################################################
            PUMBA_PIDS_SERVER=()
            case "$NETWORK_PROFILE" in
              simple)
                [[ "$LOSS_PERC" != "0" ]] && {
                  echo "   ↳ Applying static loss: ${LOSS_PERC}%"
                  pumba netem --duration 1h --interface $NETIF \
                    loss --percent "$LOSS_PERC" "$OQS_SERVER" & PUMBA_PIDS_SERVER+=($!)
                }
                [[ "$DELAY_MS" != "0" ]] && {
                  echo "   ↳ Applying fixed delay: ${DELAY_MS} ms"
                  pumba netem --duration 1h --interface $NETIF \
                    delay --time "$DELAY_MS" --jitter 0 "$OQS_SERVER" & PUMBA_PIDS_SERVER+=($!)
                }
                ;;
              stable|unstable)
                args=("${STABLE_GEMODEL[@]}")
                [[ "$NETWORK_PROFILE" == "unstable" ]] && args=("${UNSTABLE_GEMODEL[@]}")
                echo "   ↳ Applying ${NETWORK_PROFILE} network profile (loss-gemodel pg${args[0]} pb${args[1]} h${args[2]} k${args[3]})"
                pumba netem --duration 1h --interface $NETIF \
                  loss-gemodel --pg "${args[0]}" --pb "${args[1]}" \
                  --one-h "${args[2]}" --one-k "${args[3]}" "$OQS_SERVER" & PUMBA_PIDS_SERVER+=($!)
                ;;
            esac
           

            sleep 2
            echo "    Executing docker Client... $IP"

                #SSL_DIR="$HOME/captures/sslkeys"

            if [ "$PROTOCOL" = "quic" ] && [ "$CAPTURE_MODE" = "captureKey" ]; then
                mkdir -p "$SSL_DIR"

                SSLKEY_NAME="sslkeys_client_${SIG_ALG}_${KEM}.log"
                SSLKEY_PATH="$SSL_DIR/$SSLKEY_NAME"

                echo "[INFO] QUIC capture mode client: saving SSL keys to $SSLKEY_PATH"
                export SSLKEYLOGFILE="$SSLKEY_PATH"
            fi

           
            docker create --cap-add=NET_ADMIN \
                --network localNet \
                --name $OQS_CLIENT  \
                -v cert:/cert \
                -v "$SSL_DIR":/sslkeys \
                -e DOCKER_HOST=$IP \
                -e TC_DELAY=0ms  \
                -e TC_LOSS=0% \
                -e CERT_PATH=/cert/ \
                -e KEM_ALG=$KEM \
                -e SIG_ALG=$SIG_ALG \
                -e USE_TLS=$USE_TLS \
                -e NUM_RUNS=$NUM_RUNS \
                -e MUTUAL=$MUTUAL_AUTHENTICATION \
                $( [ "$PROTOCOL" = "quic" ]  && [ "$CAPTURE_MODE" = "captureKey" ] && echo "-e SSL_DIR=/sslkeys" ) \
                "$IMAGE" sleep infinity


            docker start $OQS_CLIENT

            echo "     Docker $OQS_CLIENT executed ... "
            #sleep 2    

            ############################################################################
            #  NETWORK IMPAIRMENTS (Pumba)
            ############################################################################
            PUMBA_PIDS_CLIENT=()
            case "$NETWORK_PROFILE" in
              simple)
                [[ "$DELAY_MS" != "0" ]] && {
                  echo "   ↳ Applying fixed delay: ${DELAY_MS} ms"
                  pumba netem --duration 1h --interface $NETIF \
                    delay --time "$DELAY_MS" --jitter 0 "$OQS_CLIENT" & PUMBA_PIDS_CLIENT+=($!)
                }
                ;;
            esac
            #sleep 3

            echo ""
            echo "**************************"
            echo "     Executing test  ... "

            docker exec -it $OQS_CLIENT ./perftestClientTlsQuic.sh

            echo "     Waiting  ... "
            sleep 3

         echo "   Shutting down server and impairments..."
        
         docker kill $OQS_SERVER &>/dev/null || true
         docker kill $OQS_CLIENT &>/dev/null || true
         #for pid in "${PUMBA_PIDS[@]}"; do kill -9 "$pid" &>/dev/null || true; done
    done

done

sleep 3

cleaning
echo "✅  Cleanup complete. Tests finished."
