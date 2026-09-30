#!/bin/sh
set -eu

: "${DEPLOYMENT_ENVIRONMENT:?DEPLOYMENT_ENVIRONMENT is required}"
: "${DEPLOYMENT_IMAGE_REPOSITORY:?DEPLOYMENT_IMAGE_REPOSITORY is required}"
: "${DEPLOYMENT_COMMIT_SHA:?DEPLOYMENT_COMMIT_SHA is required}"
: "${DEPLOYMENT_COMPOSE_OVERRIDE:?DEPLOYMENT_COMPOSE_OVERRIDE is required}"
: "${DEPLOYMENT_API_ENV_FILE:?DEPLOYMENT_API_ENV_FILE is required}"
: "${DEPLOYMENT_BOT_ENV_FILE:?DEPLOYMENT_BOT_ENV_FILE is required}"

PROMETHEUS_CONFIG_PATH="${PROMETHEUS_CONFIG_PATH:-monitoring/prometheus/prometheus.yml}"
PROMETHEUS_RULES_PATH="${PROMETHEUS_RULES_PATH:-monitoring/prometheus/alerts.yml}"
ALERTMANAGER_CONFIG_PATH="${ALERTMANAGER_CONFIG_PATH:-monitoring/alertmanager/alertmanager.yml}"
RESULT_PATH="${MONITORING_RESULT_PATH:-monitoring-result.json}"
ALERTMANAGER_RECEIVER_TOKEN_TMP=""

case "${DEPLOYMENT_ENVIRONMENT}:${DEPLOYMENT_COMPOSE_OVERRIDE}" in
    staging:deployment/compose.staging.yml) ;;
    production:deployment/compose.production.yml) ;;
    *)
        printf 'Monitoring deployment environment is invalid.\n' >&2
        exit 2
        ;;
esac

if [ ! -f "$PROMETHEUS_CONFIG_PATH" ] ||
    [ -L "$PROMETHEUS_CONFIG_PATH" ]; then
    printf 'Prometheus configuration is unavailable.\n' >&2
    exit 2
fi

config_size="$(
    wc -c < "$PROMETHEUS_CONFIG_PATH" |
        tr -d ' '
)"

case "$config_size" in
    ''|*[!0-9]*)
        printf 'Prometheus configuration size is invalid.\n' >&2
        exit 2
        ;;
esac

if [ "$config_size" -gt 65536 ]; then
    printf 'Prometheus configuration exceeds size limit.\n' >&2
    exit 2
fi

if [ ! -f "$PROMETHEUS_RULES_PATH" ] ||
    [ -L "$PROMETHEUS_RULES_PATH" ]; then
    printf 'Prometheus alert rules are unavailable.\n' >&2
    exit 2
fi

rules_size="$(
    wc -c < "$PROMETHEUS_RULES_PATH" |
        tr -d ' '
)"

case "$rules_size" in
    ''|*[!0-9]*)
        printf 'Prometheus alert rules size is invalid.\n' >&2
        exit 2
        ;;
esac

if [ "$rules_size" -gt 65536 ]; then
    printf 'Prometheus alert rules exceed size limit.\n' >&2
    exit 2
fi

if [ ! -f "$ALERTMANAGER_CONFIG_PATH" ] ||
    [ -L "$ALERTMANAGER_CONFIG_PATH" ]; then
    printf 'Alertmanager configuration is unavailable.\n' >&2
    exit 2
fi

alertmanager_config_size="$(
    wc -c < "$ALERTMANAGER_CONFIG_PATH" |
        tr -d ' '
)"

case "$alertmanager_config_size" in
    ''|*[!0-9]*)
        printf 'Alertmanager configuration size is invalid.\n' >&2
        exit 2
        ;;
esac

if [ "$alertmanager_config_size" -gt 65536 ]; then
    printf 'Alertmanager configuration exceeds size limit.\n' >&2
    exit 2
fi

PROJECT_NAME="ai-devsecops-${DEPLOYMENT_ENVIRONMENT}"
HELPER_NAME="${PROJECT_NAME}-prometheus-config-provision"
ALERTMANAGER_HELPER_NAME="${PROJECT_NAME}-alertmanager-config-provision"
ALERTMANAGER_SECRET_HELPER_NAME="${PROJECT_NAME}-alertmanager-secret-provision"

export DOCKER_HOST="ssh://deployment-target"
export DEPLOYMENT_API_ENV_FILE
export DEPLOYMENT_BOT_ENV_FILE

compose_command() {
    docker compose \
        --project-name "$PROJECT_NAME" \
        --file deployment/compose.yml \
        --file "$DEPLOYMENT_COMPOSE_OVERRIDE" \
        "$@"
}

write_result() {
    status="$1"

    printf \
        '{"status":"%s","environment":"%s","target_commit_sha":"%s"}\n' \
        "$status" \
        "$DEPLOYMENT_ENVIRONMENT" \
        "$DEPLOYMENT_COMMIT_SHA" \
        > "$RESULT_PATH"
}

cleanup_containers() {
    docker rm -f "$HELPER_NAME" >/dev/null 2>&1 || true
    docker rm -f "$ALERTMANAGER_HELPER_NAME" >/dev/null 2>&1 || true
    docker rm -f "$ALERTMANAGER_SECRET_HELPER_NAME" >/dev/null 2>&1 || true
}

cleanup_helper() {
    cleanup_containers

    if [ -n "$ALERTMANAGER_RECEIVER_TOKEN_TMP" ]; then
        rm -f "$ALERTMANAGER_RECEIVER_TOKEN_TMP"
    fi
}

fail_monitoring() {
    cleanup_helper
    write_result "failed"
    printf 'MONITORING_RESULT=failed\n' >&2
    printf 'CORE_APPLICATION_ROLLBACK_ATTEMPTED=false\n' >&2
    exit 1
}

trap cleanup_helper EXIT HUP INT TERM

if [ ! -f "$DEPLOYMENT_API_ENV_FILE" ] ||
    [ -L "$DEPLOYMENT_API_ENV_FILE" ]; then
    printf 'Deployment API environment file is unavailable.\n' >&2
    fail_monitoring
fi

api_env_size="$(
    wc -c < "$DEPLOYMENT_API_ENV_FILE" |
        tr -d ' '
)"

case "$api_env_size" in
    ''|*[!0-9]*)
        printf 'Deployment API environment file size is invalid.\n' >&2
        fail_monitoring
        ;;
esac

if [ "$api_env_size" -gt 262144 ]; then
    printf 'Deployment API environment file exceeds size limit.\n' >&2
    fail_monitoring
fi

umask 077

if ! ALERTMANAGER_RECEIVER_TOKEN_TMP="$(mktemp)"; then
    printf 'Alertmanager receiver credential staging failed.\n' >&2
    fail_monitoring
fi

if ! awk '
BEGIN {
    prefix = "ALERTMANAGER_RECEIVER_TOKEN="
    found = 0
}

{
    sub(/\r$/, "", $0)
}

index($0, prefix) == 1 {
    found += 1

    if (found != 1) {
        exit 2
    }

    value = substr($0, length(prefix) + 1)

    if (length(value) != 50) {
        exit 3
    }

    if (substr(value, 1, 6) != "amsec_") {
        exit 4
    }

    encoded = substr(value, 7)

    if (length(encoded) != 44) {
        exit 5
    }

    if (substr(encoded, 44, 1) != "=") {
        exit 6
    }

    body = substr(encoded, 1, 43)

    if (body ~ /[^A-Za-z0-9+\/]/) {
        exit 7
    }

    final_data_character = substr(encoded, 43, 1)

    if (final_data_character !~ /^[AEIMQUYcgkosw048]$/) {
        exit 9
    }

    printf "%s", value
}

END {
    if (found != 1) {
        exit 8
    }
}
' "$DEPLOYMENT_API_ENV_FILE" > "$ALERTMANAGER_RECEIVER_TOKEN_TMP"; then
    printf 'Alertmanager receiver credential configuration is invalid.\n' >&2
    fail_monitoring
fi

if ! chmod 600 "$ALERTMANAGER_RECEIVER_TOKEN_TMP"; then
    printf 'Alertmanager receiver credential staging permissions failed.\n' >&2
    fail_monitoring
fi

receiver_token_size="$(
    wc -c < "$ALERTMANAGER_RECEIVER_TOKEN_TMP" |
        tr -d ' '
)"

if [ "$receiver_token_size" != "50" ]; then
    printf 'Alertmanager receiver credential size is invalid.\n' >&2
    fail_monitoring
fi

service_ids() {
    service_name="$1"

    docker ps -aq \
        --filter "label=com.docker.compose.project=${PROJECT_NAME}" \
        --filter "label=com.docker.compose.service=${service_name}"
}

count_ids() {
    ids="$1"

    if [ -z "$ids" ]; then
        printf '0'
        return
    fi

    printf '%s\n' "$ids" |
        wc -w |
        tr -d ' '
}

if ! compose_command \
    --profile monitoring \
    config --quiet; then
    fail_monitoring
fi

if ! compose_command \
    --profile monitoring \
    pull prometheus; then
    fail_monitoring
fi

if ! compose_command \
    --profile monitoring \
    pull alertmanager; then
    fail_monitoring
fi

existing_ids="$(service_ids prometheus)"

if [ -n "$existing_ids" ]; then
    for container_id in $existing_ids; do
        if ! docker rm -f "$container_id" >/dev/null; then
            fail_monitoring
        fi
    done
fi

if ! compose_command \
    --profile monitoring \
    create prometheus; then
    fail_monitoring
fi

prometheus_ids="$(service_ids prometheus)"

if [ "$(count_ids "$prometheus_ids")" != "1" ]; then
    fail_monitoring
fi

prometheus_id="$prometheus_ids"

config_volume="$(
    docker inspect \
        --format '{{range .Mounts}}{{if eq .Destination "/etc/prometheus"}}{{.Name}}{{end}}{{end}}' \
        "$prometheus_id"
)"

if [ -z "$config_volume" ]; then
    fail_monitoring
fi

cleanup_containers

if ! docker create \
    --name "$HELPER_NAME" \
    --network none \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --volume "${config_volume}:/config" \
    "prom/prometheus:v3.13.2" \
    >/dev/null; then
    fail_monitoring
fi

if ! docker cp \
    "$PROMETHEUS_CONFIG_PATH" \
    "${HELPER_NAME}:/config/prometheus.yml"; then
    fail_monitoring
fi

if ! docker cp \
    "$PROMETHEUS_RULES_PATH" \
    "${HELPER_NAME}:/config/alerts.yml"; then
    fail_monitoring
fi

cleanup_containers

if ! docker run \
    --rm \
    --network none \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --volume "${config_volume}:/etc/prometheus:ro" \
    --entrypoint /bin/promtool \
    "prom/prometheus:v3.13.2" \
    check rules /etc/prometheus/alerts.yml; then
    fail_monitoring
fi

if ! docker run \
    --rm \
    --network none \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --volume "${config_volume}:/etc/prometheus:ro" \
    --entrypoint /bin/promtool \
    "prom/prometheus:v3.13.2" \
    check config /etc/prometheus/prometheus.yml; then
    fail_monitoring
fi

existing_alertmanager_ids="$(service_ids alertmanager)"

if [ -n "$existing_alertmanager_ids" ]; then
    for container_id in $existing_alertmanager_ids; do
        if ! docker rm -f "$container_id" >/dev/null; then
            fail_monitoring
        fi
    done
fi

if ! compose_command \
    --profile monitoring \
    create alertmanager; then
    fail_monitoring
fi

alertmanager_ids="$(service_ids alertmanager)"

if [ "$(count_ids "$alertmanager_ids")" != "1" ]; then
    fail_monitoring
fi

alertmanager_id="$alertmanager_ids"

alertmanager_config_volume="$(
    docker inspect \
        --format '{{range .Mounts}}{{if eq .Destination "/etc/alertmanager"}}{{.Name}}{{end}}{{end}}' \
        "$alertmanager_id"
)"

if [ -z "$alertmanager_config_volume" ]; then
    fail_monitoring
fi

cleanup_containers

if ! docker create \
    --name "$ALERTMANAGER_HELPER_NAME" \
    --network none \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --volume "${alertmanager_config_volume}:/config" \
    "prom/alertmanager:v0.33.1" \
    >/dev/null; then
    fail_monitoring
fi

if ! docker cp \
    "$ALERTMANAGER_CONFIG_PATH" \
    "${ALERTMANAGER_HELPER_NAME}:/config/alertmanager.yml"; then
    fail_monitoring
fi

docker rm -f "$ALERTMANAGER_SECRET_HELPER_NAME" >/dev/null 2>&1 || true

if ! docker run \
    --rm \
    --name "$ALERTMANAGER_SECRET_HELPER_NAME" \
    --network none \
    --read-only \
    --user 0:0 \
    --cap-drop ALL \
    --cap-add CHOWN \
    --security-opt no-new-privileges \
    --volume "${alertmanager_config_volume}:/config" \
    --entrypoint /bin/sh \
    "prom/alertmanager:v0.33.1" \
    -eu -c 'chown 0:0 /config/alertmanager.yml; chmod 0444 /config/alertmanager.yml; chown nobody:nobody /config/alertmanager.yml'; then
    printf 'Alertmanager configuration permissions normalization failed.\n' >&2
    fail_monitoring
fi

docker rm -f "$ALERTMANAGER_SECRET_HELPER_NAME" >/dev/null 2>&1 || true

if ! docker run \
    --rm \
    --name "$ALERTMANAGER_SECRET_HELPER_NAME" \
    --interactive \
    --network none \
    --read-only \
    --user 0:0 \
    --cap-drop ALL \
    --cap-add CHOWN \
    --security-opt no-new-privileges \
    --volume "${alertmanager_config_volume}:/config" \
    --entrypoint /bin/sh \
    "prom/alertmanager:v0.33.1" \
    -eu -c 'chown 0:0 /config; chmod 0755 /config; rm -f /config/receiver-token; umask 077; cat > /config/receiver-token; chmod 0400 /config/receiver-token; chown nobody:nobody /config/receiver-token' \
    < "$ALERTMANAGER_RECEIVER_TOKEN_TMP"; then
    printf 'Alertmanager receiver credential provisioning failed.\n' >&2
    fail_monitoring
fi

rm -f "$ALERTMANAGER_RECEIVER_TOKEN_TMP"
ALERTMANAGER_RECEIVER_TOKEN_TMP=""

cleanup_helper

if ! docker run \
    --rm \
    --network none \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --volume "${alertmanager_config_volume}:/etc/alertmanager:ro" \
    --entrypoint /bin/amtool \
    "prom/alertmanager:v0.33.1" \
    check-config /etc/alertmanager/alertmanager.yml \
    --enable-feature=utf8-strict-mode; then
    fail_monitoring
fi

if ! compose_command \
    --profile monitoring \
    up \
    --detach \
    --no-deps \
    --pull never \
    alertmanager; then
    fail_monitoring
fi

alertmanager_ids="$(service_ids alertmanager)"

if [ "$(count_ids "$alertmanager_ids")" != "1" ]; then
    fail_monitoring
fi

alertmanager_id="$alertmanager_ids"

alertmanager_ready="false"

for attempt in 1 2 3 4 5 6 7 8 9 10 11 12; do
    printf 'ALERTMANAGER_READINESS_ATTEMPT=%s/12\n' "$attempt"

    if docker exec "$alertmanager_id" \
        /bin/wget \
        -q \
        -O /dev/null \
        http://127.0.0.1:9093/-/ready; then
        alertmanager_ready="true"
        break
    fi

    sleep 5
done

if [ "$alertmanager_ready" != "true" ]; then
    fail_monitoring
fi

alertmanager_published_port="$(
    docker port "$alertmanager_id" 9093/tcp 2>/dev/null ||
        true
)"

if [ -n "$alertmanager_published_port" ]; then
    fail_monitoring
fi

expected_network="${PROJECT_NAME}_monitoring"

alertmanager_network_names="$(
    docker inspect \
        --format '{{range $name, $settings := .NetworkSettings.Networks}}{{println $name}}{{end}}' \
        "$alertmanager_id"
)"

if [ "$(count_ids "$alertmanager_network_names")" != "1" ]; then
    fail_monitoring
fi

if [ "$alertmanager_network_names" != "$expected_network" ]; then
    fail_monitoring
fi

if ! compose_command \
    --profile monitoring \
    up \
    --detach \
    --no-deps \
    --pull never \
    prometheus; then
    fail_monitoring
fi

prometheus_ids="$(service_ids prometheus)"

if [ "$(count_ids "$prometheus_ids")" != "1" ]; then
    fail_monitoring
fi

prometheus_id="$prometheus_ids"

ready="false"

for attempt in 1 2 3 4 5 6 7 8 9 10 11 12; do
    printf 'PROMETHEUS_READINESS_ATTEMPT=%s/12\n' "$attempt"

    if docker exec "$prometheus_id" \
        /bin/wget \
        -q \
        -O /dev/null \
        http://127.0.0.1:9090/-/ready; then
        ready="true"
        break
    fi

    sleep 5
done

if [ "$ready" != "true" ]; then
    fail_monitoring
fi

published_port="$(
    docker port "$prometheus_id" 9090/tcp 2>/dev/null ||
        true
)"

if [ -n "$published_port" ]; then
    fail_monitoring
fi

expected_network="${PROJECT_NAME}_monitoring"

network_names="$(
    docker inspect \
        --format '{{range $name, $settings := .NetworkSettings.Networks}}{{println $name}}{{end}}' \
        "$prometheus_id"
)"

if [ "$(count_ids "$network_names")" != "1" ]; then
    fail_monitoring
fi

if [ "$network_names" != "$expected_network" ]; then
    fail_monitoring
fi

network_internal="$(
    docker network inspect \
        --format '{{.Internal}}' \
        "$expected_network"
)"

if [ "$network_internal" != "true" ]; then
    fail_monitoring
fi

target_up="false"

for attempt in 1 2 3 4 5 6 7 8 9 10 11 12; do
    printf 'PROMETHEUS_SCRAPE_ATTEMPT=%s/12\n' "$attempt"

    response="$(
        docker exec "$prometheus_id" \
            /bin/wget \
            -q \
            -O - \
            'http://127.0.0.1:9090/api/v1/query?query=up%7Bjob%3D%22sample-app%22%7D' \
            2>/dev/null ||
            true
    )"

    if printf '%s' "$response" |
        grep -q '"status":"success"' &&
        printf '%s' "$response" |
            grep -q '"job":"sample-app"' &&
        printf '%s' "$response" |
            grep -Eq '"value":\[[^]]*,"1"\]'; then
        target_up="true"
        break
    fi

    sleep 5
done

if [ "$target_up" != "true" ]; then
    fail_monitoring
fi

write_result "deployed"

printf 'MONITORING_RESULT=deployed\n'
printf 'PROMETHEUS_READY=true\n'
printf 'PROMETHEUS_TARGET_UP=true\n'
printf 'PROMETHEUS_HOST_PORT_PUBLISHED=false\n'
printf 'ALERTMANAGER_READY=true\n'
printf 'ALERTMANAGER_HOST_PORT_PUBLISHED=false\n'
printf 'MONITORING_NETWORK_INTERNAL=true\n'
printf 'CORE_APPLICATION_ROLLBACK_ATTEMPTED=false\n'
printf 'SECRET_VALUES_DISPLAYED=false\n'
