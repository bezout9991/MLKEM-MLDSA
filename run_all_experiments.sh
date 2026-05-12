#!/usr/bin/env bash
set -uo pipefail

###############################################################################
#  Script d'automatisation complète des expériences ML-DSA × ML-KEM × HQC
#
#  Usage:
#    ./run_all_experiments.sh                  → tout exécuter
#    ./run_all_experiments.sh resume            → saute les scénarios complétés
#    ./run_all_experiments.sh start-from <n>   → démarre au scénario n
#
#  Scénarios (ordre — dégradation d'abord, ideal en dernier) :
#    1  africa_degraded  (200ms, 10%)
#    2  africa_backbone  (200ms, 4%)
#    3  africa_local     (35ms, 2%)
#    4  ge_stable
#    5  ge_unstable
#    6  ideal            (0ms, 0%)
#
#  Les scripts d'analyse/plots sont lancés automatiquement après chaque
#  scénario, uniquement quand TOUS les CSV nécessaires sont disponibles.
###############################################################################

export PATH="$HOME/bin:$HOME/.local/bin:/usr/local/bin:/usr/bin:/bin:$PATH"

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT_DIR"

IMAGE="uma-tls-quic-pq-34"
NUM_RUNS=500
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
CMD=${1:-run}
START_FROM=${2:-1}

###############################################################################
#  Utilitaires
###############################################################################

log() {
    local msg="[$(date '+%F %T')] $*"
    echo "$msg"
}

separator() {
    log "======================================================================"
}

clean_dir() {
    local dir="$1"
    if [[ -d "$dir" ]]; then
        log "  Nettoyage: $dir"
        find "$dir" -mindepth 1 -delete 2>/dev/null || true
    else
        mkdir -p "$dir"
        log "  Création: $dir"
    fi
}

cleanup_containers() {
    local running
    running=$(docker ps -aq 2>/dev/null)
    if [[ -n "$running" ]]; then
        log "  🧹 Suppression des containers Docker..."
        docker rm -f $running 2>/dev/null || true
    fi
}

prepare_study_dirs() {
    local study_dir="$1"
    log "Préparation des répertoires dans $study_dir"
    clean_dir "${study_dir}/TLS/csv"
    clean_dir "${study_dir}/TLS/csv/ge"
    clean_dir "${study_dir}/TLS/log"
    clean_dir "${study_dir}/TLS/log/ge"
    clean_dir "${study_dir}/TLS/plots"
    clean_dir "${study_dir}/QUIC/csv"
    clean_dir "${study_dir}/QUIC/csv/ge"
    clean_dir "${study_dir}/QUIC/log"
    clean_dir "${study_dir}/QUIC/log/ge"
    clean_dir "${study_dir}/QUIC/plots"
    clean_dir "${study_dir}/Analysis"
    clean_dir "${study_dir}/plots"
}

# Vérifie si un scénario est complété (tous les CSV ont >= NUM_RUNS data lines)
scenario_completed() {
    local study_dir=$1
    local protocol_upper=$2
    local scenario=$3
    local study_name=$4   # "pq" ou "hqc"
    local sigs=("ed25519" "secp384r1" "secp521r1" "mldsa44" "mldsa65" "mldsa87")
    local proto_lower
    proto_lower=$(echo "$protocol_upper" | tr '[:upper:]' '[:lower:]')

    for sig in "${sigs[@]}"; do
        local csv_file
        if [[ "$study_name" == "hqc" && "$scenario" == "ideal" ]]; then
            csv_file="${study_dir}/${protocol_upper}/csv/${sig}_${proto_lower}_hqc.csv"
        else
            csv_file="${study_dir}/${protocol_upper}/csv/${sig}_${proto_lower}_${scenario}.csv"
        fi
        if [[ ! -f "$csv_file" ]]; then
            return 1
        fi
        local count
        count=$(wc -l < "$csv_file")
        count=$((count - 1))  # -1 pour le header
        if [[ "$count" -lt "$NUM_RUNS" ]]; then
            return 1
        fi
    done
    return 0
}

###############################################################################
#  parse_results : génère les CSV (colonne=KEM, ligne=run)
#  Les CSV GE sont écrits dans csv/ge/
#  Les CSV HQC ideal sont renommés en _hqc.csv
###############################################################################

parse_results() {
    local log_file=$1
    local study_dir=$2
    local protocol=$3
    local scenario=$4

    if [[ ! -f "$log_file" ]]; then
        log "  ⚠️  Log introuvable: $log_file — pas de CSV généré."
        return
    fi

    local protocol_upper
    protocol_upper=$(echo "$protocol" | tr '[:lower:]' '[:upper:]')

    local tmpdir
    tmpdir=$(mktemp -d)

    local current_sig=""
    local current_kem=""
    local in_results=false
    local -A sig_kem_list
    local -A sig_kem_count

    while IFS= read -r line; do
        if [[ "$line" == *"Executing for SIG_ALG:"* ]] || [[ "$line" == *"Exécution pour SIG_ALG:"* ]]; then
            current_sig=$(echo "$line" | grep -oP 'SIG_ALG: \K\S+')
            current_kem=""
            in_results=false
            continue
        fi

        if [[ "$line" == *"KEM:"* ]]; then
            current_kem=$(echo "$line" | grep -oP 'KEM: \K\S+')
            in_results=false
            if [[ -z "${sig_kem_count[$current_sig]:-}" ]]; then
                sig_kem_count[$current_sig]=1
                sig_kem_list[$current_sig]="$current_kem"
            else
                local already=0
                IFS=':' read -ra existing <<< "${sig_kem_list[$current_sig]}"
                for ek in "${existing[@]}"; do
                    [[ "$ek" == "$current_kem" ]] && { already=1; break; }
                done
                if [[ "$already" -eq 0 ]]; then
                    sig_kem_count[$current_sig]=$((${sig_kem_count[$current_sig]} + 1))
                    sig_kem_list[$current_sig]="${sig_kem_list[$current_sig]}:${current_kem}"
                fi
            fi
            touch "${tmpdir}/${current_sig}_${current_kem}.dat"
            continue
        fi

        if [[ "$line" == *"Executing test"* ]] || [[ "$line" == *"Exécution du test"* ]]; then
            in_results=true
            continue
        fi

        if $in_results && [[ "$line" == *"Handshake duration:"* ]]; then
            local duration
            duration=$(echo "$line" | grep -oP 'Handshake duration: \K[0-9.]+')
            if [[ -n "$duration" && -n "$current_sig" && -n "$current_kem" ]]; then
                echo "$duration" >> "${tmpdir}/${current_sig}_${current_kem}.dat"
            fi
            continue
        fi
    done < "$log_file"

    # Détermine le sous-dossier de sortie
    local csv_out_dir="${study_dir}/${protocol_upper}/csv"
    local scenario_suffix="$scenario"
    if [[ "$scenario" == "ge_stable" || "$scenario" == "ge_unstable" ]]; then
        csv_out_dir="${csv_out_dir}/ge"
        mkdir -p "$csv_out_dir"
    fi
    # HQC ideal → suffixe _hqc
    if [[ "$study_dir" == *"hqc"* && "$scenario" == "ideal" ]]; then
        scenario_suffix="hqc"
    fi

    for sig in "${!sig_kem_count[@]}"; do
        local csv_file="${csv_out_dir}/${sig}_${protocol}_${scenario_suffix}.csv"
        IFS=':' read -ra kem_arr <<< "${sig_kem_list[$sig]}"

        # Vérifie que tous les fichiers .dat ont le même nombre de lignes
        local n_lines=0
        local all_ok=true
        for kem in "${kem_arr[@]}"; do
            if [[ ! -f "${tmpdir}/${sig}_${kem}.dat" ]]; then
                all_ok=false
                break
            fi
            local lines
            lines=$(wc -l < "${tmpdir}/${sig}_${kem}.dat")
            if [[ "$n_lines" -eq 0 ]]; then
                n_lines=$lines
            elif [[ "$lines" -ne "$n_lines" ]]; then
                log "  ⚠️  Lignes incohérentes pour $sig/$kem: $lines vs $n_lines"
                all_ok=false
                break
            fi
        done

        if ! $all_ok || [[ "$n_lines" -eq 0 ]]; then
            log "  ⚠️  Données incomplètes pour $sig — CSV non généré."
            continue
        fi

        # Header
        local header=""
        for ki in "${!kem_arr[@]}"; do
            if [[ "$ki" -eq 0 ]]; then
                header="${kem_arr[$ki]}"
            else
                header="${header},${kem_arr[$ki]}"
            fi
        done
        echo "$header" > "$csv_file"

        # Données
        local paste_args=()
        for kem in "${kem_arr[@]}"; do
            paste_args+=("${tmpdir}/${sig}_${kem}.dat")
        done
        paste -d',' "${paste_args[@]}" >> "$csv_file"

        log "  ✅ CSV : ${sig}_${protocol}_${scenario_suffix}.csv (${#kem_arr[@]} KEMs, ${n_lines} runs)"
    done

    rm -rf "$tmpdir"
}

###############################################################################
#  run_analysis_and_plots : lance les scripts Python quand les données sont prêtes
###############################################################################

run_analysis_and_plots() {
    local study_dir=$1
    local scenario=$2
    local study_name=$3   # "pq" ou "hqc"

    local scripts_dir="${study_dir}/scripts"
    local plots_dir="${study_dir}/plots"
    local analysis_dir="${study_dir}/Analysis"
    mkdir -p "$plots_dir" "$analysis_dir"

    log "  📊 Vérification des données pour analyses/plots ($scenario)..."

    # ── PQ-signatures (5-) ──────────────────────────────────────────────────
    if [[ "$study_name" == "pq" ]]; then
        # ideal → analysis_pq_signatures + plot_pq_signatures + plot_violins
        if [[ "$scenario" == "ideal" ]]; then
            if scenario_completed "$study_dir" "TLS" "ideal" "pq" && \
               scenario_completed "$study_dir" "QUIC" "ideal" "pq"; then
                log "  📈 Lancement analyses ideal PQ..."
                python3 "${scripts_dir}/analysis_pq_signatures.py" --data-dir "$study_dir" \
                    > "${analysis_dir}/analysis_ideal.txt" 2>&1 || true
                python3 "${scripts_dir}/plot_pq_signatures.py" --data-dir "$study_dir" --out-dir "$plots_dir" \
                    > "${plots_dir}/plot_ideal.log" 2>&1 || true
                python3 "${scripts_dir}/plot_violins_phase5.py" --data-dir "$study_dir" \
                    > "${plots_dir}/plot_violins.log" 2>&1 || true
                log "  ✅ Analyses/plots ideal PQ terminées."
            else
                log "  ⏳ Données ideal PQ incomplètes — analyses reportées."
            fi
        fi

        # africa_local ou africa_backbone → analysis_africa + plot_africa
        # Nécessite: ideal + africa_local + africa_backbone + africa_degraded
        if [[ "$scenario" == "africa_local" || "$scenario" == "africa_backbone" ]]; then
            local africa_ready=true
            for sc in ideal africa_local africa_backbone africa_degraded; do
                if ! scenario_completed "$study_dir" "TLS" "$sc" "pq" || \
                   ! scenario_completed "$study_dir" "QUIC" "$sc" "pq"; then
                    africa_ready=false
                    break
                fi
            done
            if $africa_ready; then
                log "  📈 Lancement analyses Africa PQ..."
                python3 "${scripts_dir}/analysis_africa_scenarios.py" --data-dir "$study_dir" \
                    > "${analysis_dir}/analysis_africa.txt" 2>&1 || true
                python3 "${scripts_dir}/plot_africa_scenarios.py" --data-dir "$study_dir" --out-dir "$plots_dir" \
                    > "${plots_dir}/plot_africa.log" 2>&1 || true
                log "  ✅ Analyses/plots Africa PQ terminées."
            else
                log "  ⏳ Données Africa PQ incomplètes — analyses reportées."
            fi
        fi

        # ge_stable ou ge_unstable → analysis_ge
        # Nécessite: ideal + africa_local + africa_degraded + ge_stable + ge_unstable
        if [[ "$scenario" == "ge_stable" || "$scenario" == "ge_unstable" ]]; then
            local ge_ready=true
            for sc in ideal africa_local africa_degraded ge_stable ge_unstable; do
                if ! scenario_completed "$study_dir" "TLS" "$sc" "pq" || \
                   ! scenario_completed "$study_dir" "QUIC" "$sc" "pq"; then
                    ge_ready=false
                    break
                fi
            done
            if $ge_ready; then
                log "  📈 Lancement analyses GE PQ..."
                python3 "${scripts_dir}/analysis_ge.py" --study1-dir "$study_dir" \
                    > "${analysis_dir}/analysis_ge.txt" 2>&1 || true
                log "  ✅ Analyses GE PQ terminées."
            else
                log "  ⏳ Données GE PQ incomplètes — analyses reportées."
            fi
        fi
    fi

    # ── HQC (6-) ───────────────────────────────────────────────────────────
    if [[ "$study_name" == "hqc" ]]; then
        # ideal → analysis_hqc + plot_hqc_ideal
        if [[ "$scenario" == "ideal" ]]; then
            if scenario_completed "$study_dir" "TLS" "ideal" "hqc" && \
               scenario_completed "$study_dir" "QUIC" "ideal" "hqc"; then
                log "  📈 Lancement analyses ideal HQC..."
                python3 "${scripts_dir}/analysis_hqc.py" --data-dir "$study_dir" \
                    > "${analysis_dir}/analysis_ideal.txt" 2>&1 || true
                python3 "${scripts_dir}/plot_hqc_ideal.py" --data-dir "$study_dir" --out-dir "$plots_dir" \
                    > "${plots_dir}/plot_ideal.log" 2>&1 || true
                log "  ✅ Analyses/plots ideal HQC terminées."
            else
                log "  ⏳ Données ideal HQC incomplètes — analyses reportées."
            fi
        fi

        # africa → analysis_hqc_africa + plot_hqc_africa
        if [[ "$scenario" == "africa_local" || "$scenario" == "africa_backbone" ]]; then
            local africa_ready=true
            for sc in ideal africa_local africa_backbone africa_degraded; do
                if ! scenario_completed "$study_dir" "TLS" "$sc" "hqc" || \
                   ! scenario_completed "$study_dir" "QUIC" "$sc" "hqc"; then
                    africa_ready=false
                    break
                fi
            done
            if $africa_ready; then
                log "  📈 Lancement analyses Africa HQC..."
                python3 "${scripts_dir}/analysis_hqc_africa.py" --data-dir "$study_dir" \
                    > "${analysis_dir}/analysis_africa.txt" 2>&1 || true
                python3 "${scripts_dir}/plot_hqc_africa.py" --data-dir "$study_dir" --out-dir "$plots_dir" \
                    > "${plots_dir}/plot_africa.log" 2>&1 || true
                log "  ✅ Analyses/plots Africa HQC terminées."
            else
                log "  ⏳ Données Africa HQC incomplètes — analyses reportées."
            fi
        fi

        # ge → analysis_ge
        if [[ "$scenario" == "ge_stable" || "$scenario" == "ge_unstable" ]]; then
            local ge_ready=true
            for sc in ideal africa_local africa_degraded ge_stable ge_unstable; do
                if ! scenario_completed "$study_dir" "TLS" "$sc" "hqc" || \
                   ! scenario_completed "$study_dir" "QUIC" "$sc" "hqc"; then
                    ge_ready=false
                    break
                fi
            done
            if $ge_ready; then
                log "  📈 Lancement analyses GE HQC..."
                python3 "${scripts_dir}/analysis_ge.py" --study2-dir "$study_dir" \
                    > "${analysis_dir}/analysis_ge.txt" 2>&1 || true
                log "  ✅ Analyses GE HQC terminées."
            else
                log "  ⏳ Données GE HQC incomplètes — analyses reportées."
            fi
        fi
    fi
}

###############################################################################
#  run_experiment
###############################################################################

run_experiment() {
    local launcher=$1 protocol=$2 auth_mode=$3 capture_mode=$4
    local network_profile=$5 loss_perc=$6 delay_ms=$7 study_dir=$8
    local study_name=$9

    local scenario
    case "$network_profile" in
        none)     scenario="ideal" ;;
        simple)
            if [[ "$loss_perc" -eq 2 && "$delay_ms" -eq 35 ]]; then
                scenario="africa_local"
            elif [[ "$loss_perc" -eq 4 && "$delay_ms" -eq 200 ]]; then
                scenario="africa_backbone"
            elif [[ "$loss_perc" -eq 10 && "$delay_ms" -eq 200 ]]; then
                scenario="africa_degraded"
            else
                scenario="simple_${loss_perc}p_${delay_ms}ms"
            fi
            ;;
        stable)   scenario="ge_stable" ;;
        unstable) scenario="ge_unstable" ;;
        *)        scenario="${network_profile}" ;;
    esac

    local protocol_upper
    protocol_upper=$(echo "$protocol" | tr '[:lower:]' '[:upper:]')
    local proto_lower
    proto_lower=$(echo "$protocol" | tr '[:upper:]' '[:lower:]')

    local exp_log_dir="${study_dir}/${protocol_upper}/log"
    mkdir -p "$exp_log_dir"
    local exp_log="${exp_log_dir}/${scenario}_${TIMESTAMP}.log"

    separator
    log "EXPÉRIENCE: $protocol | $network_profile | loss=${loss_perc}% | delay=${delay_ms}ms"
    log "  Scénario: $scenario | Étude: $study_name"
    log "  ── Sortie en temps réel ──"

    cleanup_containers

    local exit_code=0
    if bash "$launcher" "$protocol" "$auth_mode" "$capture_mode" "$network_profile" "$loss_perc" "$delay_ms" 2>&1 | tee "$exp_log"; then
        log "  ✅ Succès (exit code 0)"
    else
        exit_code=${PIPESTATUS[0]}
        log "  ⚠️  Terminé avec exit code $exit_code"
    fi

    parse_results "$exp_log" "$study_dir" "$proto_lower" "$scenario"
    log "  Log: $exp_log"
}

###############################################################################
#  run_study
###############################################################################

run_study() {
    local study_num=$1 launcher=$2 study_dir=$3 protocols=$4 study_name=$5

    local -a SCENARIOS=(
        "africa_degraded:simple:10:200"
        "africa_backbone:simple:4:200"
        "africa_local:simple:2:35"
        "ge_stable:stable:0:0"
        "ge_unstable:unstable:0:0"
        "ideal:none:0:0"
    )

    local start_idx=$((START_FROM - 1))

    for si in "${!SCENARIOS[@]}"; do
        if [[ "$CMD" == "start-from" && "$si" -lt "$start_idx" ]]; then
            log "  ⏭️  Scénario $((si+1)) sauté (start-from $START_FROM)."
            continue
        fi

        IFS=':' read -r scenario_name network_profile loss delay <<< "${SCENARIOS[$si]}"

        separator
        log "ÉTUDE $study_num — Scénario $((si+1))/${#SCENARIOS[@]}: $scenario_name (${loss}%, ${delay}ms)"
        separator

        IFS=',' read -ra protos <<< "$protocols"
        for proto in "${protos[@]}"; do
            run_experiment "$launcher" "$proto" "single" "nocapture" \
                "$network_profile" "$loss" "$delay" "$study_dir" "$study_name"
        done

        # Analyse et plots automatiques après chaque scénario
        run_analysis_and_plots "$study_dir" "$scenario_name" "$study_name"
    done
}

###############################################################################
#  VÉRIFICATIONS PRÉALABLES
###############################################################################

case "$CMD" in
    run)        log "🚀 Mode : exécution complète" ;;
    resume)     log "🔄 Mode : reprise (saute les scénarios complétés)" ;;
    start-from) log "▶️  Mode : démarrage au scénario $START_FROM" ;;
    *)          log "❌ Commande inconnue: $CMD"; exit 1 ;;
esac

separator
log "VÉRIFICATIONS PRÉALABLES"
separator

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    log "❌ ERREUR: L'image Docker '$IMAGE' n'existe pas."
    exit 1
fi
log "✅ Image Docker '$IMAGE' trouvée"

for launcher in Launcherv3_pq_mlkem.sh Launcherv3_pq_hqc.sh; do
    if [[ ! -f "$launcher" ]]; then
        log "❌ ERREUR: $launcher non trouvé"
        exit 1
    fi
    log "✅ $launcher trouvé"
done

if ! command -v pumba >/dev/null 2>&1; then
    log "❌ ERREUR: Le binaire 'pumba' n'est pas installé."
    exit 1
fi
log "✅ pumba trouvé ($(which pumba))"

###############################################################################
#  PRÉPARATION
###############################################################################

separator
log "PRÉPARATION DES RÉPERTOIRES"
separator

STUDY5_DIR="${PROJECT_DIR}/5- pq-signatures"
STUDY6_DIR="${PROJECT_DIR}/6- hqc"

prepare_study_dirs "$STUDY5_DIR"
prepare_study_dirs "$STUDY6_DIR"

###############################################################################
#  EXÉCUTION
###############################################################################

MLKEM_LAUNCHER="${PROJECT_DIR}/Launcherv3_pq_mlkem.sh"
HQC_LAUNCHER="${PROJECT_DIR}/Launcherv3_pq_hqc.sh"

separator
log "ÉTUDE 1 : ML-KEM × ML-DSA (5- pq-signatures)"
separator
run_study 1 "$MLKEM_LAUNCHER" "$STUDY5_DIR" "tls,quic" "pq"

separator
log "ÉTUDE 2 : HQC × ML-DSA (6- hqc)"
separator
run_study 2 "$HQC_LAUNCHER" "$STUDY6_DIR" "tls,quic" "hqc"

###############################################################################
#  RÉSUMÉ
###############################################################################

separator
log "RÉSUMÉ DE L'EXÉCUTION"
separator

log "Structure des résultats:"
log "  ${STUDY5_DIR}/"
log "    TLS/csv/   → Résultats TLS Étude 1 (ML-KEM)"
log "    QUIC/csv/  → Résultats QUIC Étude 1 (ML-KEM)"
log "    TLS/csv/ge/ → Résultats GE TLS"
log "    QUIC/csv/ge/ → Résultats GE QUIC"
log "    plots/     → Figures générées"
log "    Analysis/  → Analyses textuelles"
log "  ${STUDY6_DIR}/"
log "    TLS/csv/   → Résultats TLS Étude 2 (HQC)"
log "    QUIC/csv/  → Résultats QUIC Étude 2 (HQC)"
log "    TLS/csv/ge/ → Résultats GE TLS"
log "    QUIC/csv/ge/ → Résultats GE QUIC"
log "    plots/     → Figures générées"
log "    Analysis/  → Analyses textuelles"

csv_count5=$(find "${STUDY5_DIR}" -name "*.csv" -type f 2>/dev/null | wc -l)
csv_count6=$(find "${STUDY6_DIR}" -name "*.csv" -type f 2>/dev/null | wc -l)
log "CSV générés: ${csv_count5} (Étude 1) + ${csv_count6} (Étude 2) = $((csv_count5 + csv_count6)) total"

separator
log "✅  Toutes les expériences sont terminées !"
separator
