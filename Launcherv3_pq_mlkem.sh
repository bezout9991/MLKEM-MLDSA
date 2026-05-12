#!/bin/bash

#!/usr/bin/env bash
set -euo pipefail

# Ajouter ~/bin au PATH pour pumba et autres outils utilisateur
export PATH="$HOME/bin:$PATH"

# Forcer la version de l'API Docker (pumba utilise une ancienne version)
export DOCKER_API_VERSION="1.44"

# Vérifier que Pumba est installé
if ! command -v pumba &>/dev/null; then
    echo "ERROR: pumba not found in PATH." 
    echo "Install with:"
    echo "  mkdir -p ~/bin"
    echo "  wget -q https://github.com/alexei-led/pumba/releases/download/0.9.0/pumba_linux_amd64 -O ~/bin/pumba"
    echo "  chmod +x ~/bin/pumba"
    exit 1
fi

###############################################################################
#  PARAMÈTRES DE LIGNE DE COMMANDE
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
#  Validation des entrées
###############################################################################

# 1) Protocole
if [[ "$PROTOCOL" != "tls" && "$PROTOCOL" != "quic" ]]; then
    echo "$USAGE"
    exit 1
fi

# 2) Mode d'authentification mutuelle
if [[ "$AUTH_MODE" != "mutual" && "$AUTH_MODE" != "single" ]]; then
    echo "Invalid authentication mode: must be 'mutual' or 'single'."
    echo "$USAGE"
    exit 1
fi

# 3) Mode de capture de paquets
if [[ "$CAPTURE_MODE" != "capture" && "$CAPTURE_MODE" != "captureKey" && "$CAPTURE_MODE" != "nocapture" ]]; then
    echo "Invalid capture mode: must be 'capture', 'captureKey', or 'nocapture'."
    echo "$USAGE"
    exit 1
fi

# 4) Profil réseau
if [[ "$NETWORK_PROFILE" != "none" && "$NETWORK_PROFILE" != "simple" && "$NETWORK_PROFILE" != "stable" && "$NETWORK_PROFILE" != "unstable" ]]; then
    echo "Invalid network profile: must be 'none', 'simple', 'stable', or 'unstable'."
    echo "$USAGE"
    exit 1
fi

# 5) Pourcentage de perte de paquets (0–100)
if ! [[ "$LOSS_PERC" =~ ^[0-9]+$ ]] || (( LOSS_PERC < 0 || LOSS_PERC > 100 )); then
    echo "Invalid loss-percent: must be an integer between 0 and 100."
    echo "$USAGE"
    exit 1
fi

# 6) Délai en millisecondes (>= 0)
if ! [[ "$DELAY_MS" =~ ^[0-9]+$ ]] || (( DELAY_MS < 0 )); then
    echo "Invalid delay-ms: must be a non-negative integer."
    echo "$USAGE"
    exit 1
fi



###############################################################################
#  CONFIGURATION
###############################################################################

 NUM_RUNS=50

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
# Récupérer le paramètre de ligne de commande
 USE_TLS=$([[ "$PROTOCOL" == "tls" ]] && echo true || echo false)
 # Profils GE-model (valeurs en %)
STABLE_GEMODEL=(10 50 70 10)    # pg10 pb50 h70 k10
UNSTABLE_GEMODEL=(20 40 90 20)  # pg20 pb40 h90 k20


echo "*************************************"
echo "Paramètres valides. Démarrage avec:"
echo "  Protocole:       $PROTOCOL"
echo "  Mode d'Auth:     $AUTH_MODE"
echo "  Mode Capture:    $CAPTURE_MODE"
echo "  Profil Réseau:   $NETWORK_PROFILE"
echo "  Perte %:         $LOSS_PERC"
echo "  Délai (ms):      $DELAY_MS"
echo "  Exécutions:      $NUM_RUNS"

echo "  Signatures:      ${SUPPORTED_SIG_ALGS[*]}"
echo "  KEMS Niveau 1:   ${KEMS_L1[*]}"
echo "  KEMS Niveau 3:   ${KEMS_L3[*]}"
echo "  KEMS Niveau 5:   ${KEMS_L5[*]}"
echo "*************************************"

###############################################################################
#  Fonction: detect_platform
#    
###############################################################################

detect_platform() {
    os="$(uname -s)"
    case "$os" in
        Linux)
            echo "Exécution sur Linux" ;;
        Darwin)
            echo "Exécution sur macOS" ;;
        *)
            echo "Exécution sur: $os" ;;
    esac
}

###############################################################################
#  Fonction: launch_edgeshark
#    
###############################################################################
launch_edgeshark() {
    # 1) Variables
    URL="https://github.com/siemens/edgeshark/raw/main/deployments/wget/docker-compose-localhost.yaml"
    COMPOSE_FILE="./docker-compose-localhost.yaml"  # chemin fixe

    # 2) Télécharger (s'il a changé) le fichier Compose
    mkdir -p "$(dirname "$COMPOSE_FILE")"
    wget -q --no-cache -O "$COMPOSE_FILE" "$URL"

    # 3) Vérifier si des conteneurs sont en cours d'exécution
    #    --quiet -q retourne les IDs; s'il est vide, aucun conteneur en cours
    if [ -z "$(docker compose -f "$COMPOSE_FILE" ps -q)" ]; then
        echo "$(date '+%F %T') → Aucun conteneur actif. Démarrage de la pile..." 
        docker compose -f "$COMPOSE_FILE" up -d 
    else
        echo "$(date '+%F %T') → C'est en cours d'exécution. Rien à faire." 
    fi
}
###############################################################################
#  Fonction: lauch_Wireshark
#    
###############################################################################

lauch_Wireshark_mac(){

     if [ -d "/Applications/Wireshark.app" ]; then
                    echo "Wireshark est installé, parfait!!!"

                    if ps aux | grep -i wireshark | grep -v grep > /dev/null; then         
                        echo "Wireshark est en cours d'exécution."
                        # Attendre que l'utilisateur soit prêt
                        read -n 1 -s -r -p "Veuillez sauvegarder les données Wireshark pour exécuter une autre expérience..."
                        echo ""
                        echo "Démarrage maintenant ... "
                        open -a Wireshark

                    else
                        echo "Wireshark n'est PAS en cours d'exécution. Démarrage maintenant ... "
                        open -a Wireshark
                    fi 
            else
                echo "Wireshark n'est pas installé dans /Applications."
                exit 1
            fi

            # Attendre que l'utilisateur soit prêt
            read -n 1 -s -r -p "Configurez Wireshark et appuyez sur une touche lorsque vous êtes prêt à continuer..."
            echo ""
}

###############################################################################
#  Fonction: lauch_Wireshark
#    
###############################################################################

launch_wireshark_linux() {
    # Vérifier si la commande 'wireshark' est disponible
    if command -v wireshark >/dev/null 2>&1; then
        echo "Wireshark est installé, parfait!!!"

        # Vérifier si Wireshark est déjà en cours d'exécution (en tant qu'utilisateur courant)
        if pgrep -u "$USER" -x wireshark >/dev/null 2>&1; then
            echo "Wireshark est déjà en cours d'exécution."
        else
            echo "Wireshark n'est PAS en cours d'exécution. Démarrage maintenant..."
            # Lancer Wireshark en arrière-plan
            wireshark 
            # Laisser un moment pour démarrer
            sleep 1
        fi

        # Attendre que l'utilisateur sauvegarde ou inspecte les captures avant de continuer
        read -n 1 -s -r -p "Veuillez sauvegarder les données Wireshark pour exécuter une autre expérience, puis appuyez sur une touche pour continuer..."
        echo ""
        read -n 1 -s -r -p "Configurez Wireshark et appuyez sur une touche lorsque vous êtes prêt à continuer..."
        echo ""

    else
        echo "Wireshark n'est pas installé. Veuillez l'installer (par ex. Ubuntu/Debian: sudo apt install wireshark) et réessayer."
        exit 1
    fi
}
###############################################################################
#  Fonction: cleaning
#    
###############################################################################

cleaning(){
    docker kill $OQS_SERVER &>/dev/null || true
    docker kill $OQS_CLIENT &>/dev/null || true
    docker rm -f $OQS_SERVER $OQS_CLIENT &>/dev/null || true
    docker container prune -f &>/dev/null || true
    docker volume rm cert 2>/dev/null || true
    docker network rm localNet 2>/dev/null || true
}

detect_platform

cleaning

echo ""
echo "*************************************"
echo "***RÉSEAU ET VOLUME *****************"
echo "*************************************"

# Créer le réseau s'il n'existe pas
if ! docker network inspect localNet >/dev/null 2>&1; then
    docker network create localNet
    echo "✅ Réseau localNet créé."
else
    echo "ℹ️  Le réseau localNet existe déjà; il ne sera pas créé."
fi

# Créer le volume s'il n'existe pas
if ! docker volume inspect cert >/dev/null 2>&1; then
    docker volume create cert
    echo "✅ Volume cert créé."
else
    echo "ℹ️  Le volume cert existe déjà; il ne sera pas créé."
fi

echo "*************************************"



if [[ "$CAPTURE_MODE" == "capture" || "$CAPTURE_MODE" == "captureKey" ]]; then
    echo ""
    echo "Lancement d'edgeshark"
    launch_edgeshark
 fi   

# Liste des signatures et leurs KEMs
SIG_ALGS=("${SUPPORTED_SIG_ALGS[@]}")


for SIG_ALG in "${SIG_ALGS[@]}"; do
    echo ""
    echo " ==> Exécution pour SIG_ALG: $SIG_ALG"

    if [ "$SIG_ALG" = "ed25519" ]; then
        KEMS=("${KEMS_L1[@]}")
    elif [ "$SIG_ALG" = "secp384r1" ]; then
        KEMS=("${KEMS_L3[@]}")
    elif [ "$SIG_ALG" = "secp521r1" ]; then
        KEMS=("${KEMS_L5[@]}")
    fi

    echo ""
    echo " ==> Création des certificats et clés"
    docker run --rm -v cert:/cert -e CERT_PATH=/cert/ -e SIG_ALG=$SIG_ALG -i "$IMAGE" doCert.sh

    
    for KEM in "${KEMS[@]}"; do
        echo ""
        echo "****************"
        echo "  -> KEM: $KEM"


        
            echo ""
            echo "    Exécution du serveur Docker..."

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
               -e TC_DELAY=${DELAY_MS}ms \
               -e TC_LOSS=${LOSS_PERC}% \
               -e CERT_PATH=/cert/ \
               -e KEM_ALG=$KEM  \
               -e SIG_ALG=$SIG_ALG \
               -e USE_TLS=$USE_TLS \
               -e MUTUAL=$MUTUAL_AUTHENTICATION \
              $( [ "$PROTOCOL" = "tls" ] && [ "$CAPTURE_MODE" == "captureKey" ] && echo "-e SSL_DIR=/sslkeys" ) \
               -d $IMAGE perftestServerTlsQuic.sh
           
            sleep 3    

            echo "    Recherche de l'IP.. "
            IP=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$OQS_SERVER")
            echo "    IP..  $IP"

            
            if [[ "$CAPTURE_MODE" == "capture" || "$CAPTURE_MODE" == "captureKey" ]]; then
                echo ""
                echo "Lancement de Wireshark"

                if [[ "$os" == "Darwin" ]]; then
                    lauch_Wireshark_mac
                else
                    launch_wireshark_linux
                fi    
            fi   


############################################################################
            #  NETWORK IMPAIRMENTS (Pumba avec --tc-image)
            ############################################################################
            PUMBA_PIDS_SERVER=()
            case "$NETWORK_PROFILE" in
              simple)
                # Nettoyer les règles tc résiduelles
                docker exec "$OQS_SERVER" tc qdisc del dev "$NETIF" root 2>/dev/null || true
                # Appliquer delay+loss combiné via docker exec tc
                if [[ "$LOSS_PERC" != "0" || "$DELAY_MS" != "0" ]]; then
                  echo "   ↳ tc serveur: delay=${DELAY_MS}ms loss=${LOSS_PERC}%"
                  docker exec "$OQS_SERVER" tc qdisc replace dev "$NETIF" root netem \
                    delay "${DELAY_MS}ms" $([[ "$LOSS_PERC" != "0" ]] && echo "loss ${LOSS_PERC}%") 2>/dev/null || true
                fi
                ;;
              stable|unstable)
                args=("${STABLE_GEMODEL[@]}")
                [[ "$NETWORK_PROFILE" == "unstable" ]] && args=("${UNSTABLE_GEMODEL[@]}")
                echo "   ↳ Pumba serveur ${NETWORK_PROFILE} (pg${args[0]} pb${args[1]} h${args[2]} k${args[3]})"
                docker exec "$OQS_SERVER" tc qdisc del dev "$NETIF" root 2>/dev/null || true
                pumba netem --duration 1h --interface $NETIF \
                  --tc-image ghcr.io/alexei-led/pumba-alpine-nettools:latest \
                  loss-gemodel --pg "${args[0]}" --pb "${args[1]}" \
                  --one-h "${args[2]}" --one-k "${args[3]}" "$OQS_SERVER" & PUMBA_PIDS_SERVER+=($!)
                sleep 2
                echo "   ↳ Pumba client ${NETWORK_PROFILE} (même profil)"
                docker exec "$OQS_CLIENT" tc qdisc del dev "$NETIF" root 2>/dev/null || true
                docker exec "$OQS_CLIENT" tc qdisc add dev "$NETIF" root handle 1: default
                docker exec "$OQS_CLIENT" tc qdisc add dev "$NETIF" parent 1: handle 10: netem \
                  delay $((DELAY_MS))ms $([[ "$LOSS_PERC" != "0" ]] && echo "loss ${LOSS_PERC}%") 2>/dev/null || true
                ;;
            esac

            sleep 2
            echo "    Exécution du client Docker... $IP"

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
                -e TC_DELAY=${DELAY_MS}ms \
                -e TC_LOSS=${LOSS_PERC}% \
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
                if [[ "$DELAY_MS" != "0" || "$LOSS_PERC" != "0" ]]; then
                  echo "   ↳ Pumba client: delay=${DELAY_MS}ms loss=${LOSS_PERC}%"
                  pumba netem --duration 1h --interface $NETIF \
                    $([[ "$DELAY_MS" != "0" ]] && echo "delay --time $DELAY_MS --jitter 0") \
                    $([[ "$LOSS_PERC" != "0" ]] && echo "loss --percent $LOSS_PERC") \
                    "$OQS_CLIENT" & PUMBA_PIDS_CLIENT+=($!)
                fi
                ;;
            esac
            #sleep 3

            echo ""
            echo "**************************"
            echo "     Exécution du test  ... "

            docker exec -i $OQS_CLIENT ./perftestClientTlsQuic.sh

            echo "     Attente  ... "
            sleep 3

         echo "   Arrêt du serveur et des dégradations..."
        
         docker kill $OQS_SERVER &>/dev/null || true
         docker kill $OQS_CLIENT &>/dev/null || true
         #for pid in "${PUMBA_PIDS[@]}"; do kill -9 "$pid" &>/dev/null || true; done
    done

done

sleep 3

cleaning
echo "✅  Nettoyage terminé. Tests finis."
