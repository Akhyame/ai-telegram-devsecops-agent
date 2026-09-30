#!/bin/sh
set -eu

: "${DEPLOYMENT_ENVIRONMENT:?DEPLOYMENT_ENVIRONMENT is required}"
: "${DEPLOYMENT_IMAGE_REPOSITORY:?DEPLOYMENT_IMAGE_REPOSITORY is required}"
: "${DEPLOYMENT_COMMIT_SHA:?DEPLOYMENT_COMMIT_SHA is required}"
: "${DEPLOYMENT_COMPOSE_OVERRIDE:?DEPLOYMENT_COMPOSE_OVERRIDE is required}"
: "${DEPLOYMENT_API_ENV_FILE:?DEPLOYMENT_API_ENV_FILE is required}"
: "${DEPLOYMENT_BOT_ENV_FILE:?DEPLOYMENT_BOT_ENV_FILE is required}"

case "$DEPLOYMENT_ENVIRONMENT" in
    staging|production) ;;
    *)
        printf 'Deployment environment is invalid.\n' >&2
        exit 2
        ;;
esac

if ! printf '%s' "$DEPLOYMENT_COMMIT_SHA" |
    grep -Eq '^[0-9a-f]{40}$'; then
    printf 'Deployment commit SHA is invalid.\n' >&2
    exit 2
fi

case "$DEPLOYMENT_IMAGE_REPOSITORY" in
    *[!A-Za-z0-9._/-]*|'')
        printf 'Deployment image repository is invalid.\n' >&2
        exit 2
        ;;
esac

case "${DEPLOYMENT_ENVIRONMENT}:${DEPLOYMENT_COMPOSE_OVERRIDE}" in
    staging:deployment/compose.staging.yml) ;;
    production:deployment/compose.production.yml) ;;
    *)
        printf 'Deployment Compose override is invalid.\n' >&2
        exit 2
        ;;
esac

TARGET_SHA="$DEPLOYMENT_COMMIT_SHA"
PREVIOUS_SHA=""
PROJECT_NAME="ai-devsecops-${DEPLOYMENT_ENVIRONMENT}"
RESULT_PATH="${DEPLOYMENT_RESULT_PATH:-deployment-result.json}"

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
    result_status="$1"
    rollback_status="$2"
    active_sha="$3"

    printf \
        '{"status":"%s","environment":"%s","target_commit_sha":"%s","previous_commit_sha":"%s","active_commit_sha":"%s","rollback":"%s"}\n' \
        "$result_status" \
        "$DEPLOYMENT_ENVIRONMENT" \
        "$TARGET_SHA" \
        "$PREVIOUS_SHA" \
        "$active_sha" \
        "$rollback_status" \
        > "$RESULT_PATH"
}

service_ids() {
    service_name="$1"

    docker ps -aq \
        --filter "label=com.docker.compose.project=${PROJECT_NAME}" \
        --filter "label=com.docker.compose.service=${service_name}"
}

running_service_ids() {
    service_name="$1"

    docker ps -q \
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

capture_previous_release() {
    api_ids="$(service_ids api)"
    bot_ids="$(service_ids bot)"
    api_count="$(count_ids "$api_ids")"
    bot_count="$(count_ids "$bot_ids")"

    if [ "$api_count" = "0" ] &&
        [ "$bot_count" = "0" ]; then
        return 0
    fi

    if [ "$api_count" != "1" ] ||
        [ "$bot_count" != "1" ]; then
        return 1
    fi

    if ! api_running="$(
        docker inspect \
            --format '{{.State.Running}}' \
            "$api_ids"
    )"; then
        return 1
    fi

    if ! bot_running="$(
        docker inspect \
            --format '{{.State.Running}}' \
            "$bot_ids"
    )"; then
        return 1
    fi

    if ! api_health="$(
        docker inspect \
            --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' \
            "$api_ids"
    )"; then
        return 1
    fi

    if ! bot_health="$(
        docker inspect \
            --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' \
            "$bot_ids"
    )"; then
        return 1
    fi

    if [ "$api_running" != "true" ] ||
        [ "$bot_running" != "true" ]; then
        return 1
    fi

    if [ "$api_health" != "healthy" ] ||
        [ "$bot_health" != "healthy" ]; then
        return 1
    fi

    if ! api_image="$(
        docker inspect \
            --format '{{.Config.Image}}' \
            "$api_ids"
    )"; then
        return 1
    fi

    if ! bot_image="$(
        docker inspect \
            --format '{{.Config.Image}}' \
            "$bot_ids"
    )"; then
        return 1
    fi

    if [ "$api_image" != "$bot_image" ]; then
        return 1
    fi

    case "$api_image" in
        "$DEPLOYMENT_IMAGE_REPOSITORY:"*) ;;
        *) return 1 ;;
    esac

    previous_sha="${api_image#"$DEPLOYMENT_IMAGE_REPOSITORY:"}"

    if ! printf '%s' "$previous_sha" |
        grep -Eq '^[0-9a-f]{40}$'; then
        return 1
    fi

    PREVIOUS_SHA="$previous_sha"
}

verify_release() {
    expected_sha="$1"

    if ! api_ids="$(running_service_ids api)"; then
        return 1
    fi

    if ! bot_ids="$(running_service_ids bot)"; then
        return 1
    fi

    if [ "$(count_ids "$api_ids")" != "1" ]; then
        return 1
    fi

    if [ "$(count_ids "$bot_ids")" != "1" ]; then
        return 1
    fi

    expected_image="${DEPLOYMENT_IMAGE_REPOSITORY}:${expected_sha}"

    if ! api_image="$(
        docker inspect \
            --format '{{.Config.Image}}' \
            "$api_ids"
    )"; then
        return 1
    fi

    if ! bot_image="$(
        docker inspect \
            --format '{{.Config.Image}}' \
            "$bot_ids"
    )"; then
        return 1
    fi

    if [ "$api_image" != "$expected_image" ]; then
        return 1
    fi

    if [ "$bot_image" != "$expected_image" ]; then
        return 1
    fi

    if ! api_health="$(
        docker inspect \
            --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' \
            "$api_ids"
    )"; then
        return 1
    fi

    if ! bot_health="$(
        docker inspect \
            --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' \
            "$bot_ids"
    )"; then
        return 1
    fi

    if [ "$api_health" != "healthy" ] ||
        [ "$bot_health" != "healthy" ]; then
        return 1
    fi

    if ! docker exec "$api_ids" \
        python -c \
        "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health/ready', timeout=2).close()" \
        >/dev/null; then
        return 1
    fi

    if ! docker exec "$bot_ids" \
        python -c "import os; os.kill(1, 0)" \
        >/dev/null; then
        return 1
    fi
}

deploy_sha() {
    candidate_sha="$1"
    pull_required="$2"

    DEPLOYMENT_COMMIT_SHA="$candidate_sha"
    export DEPLOYMENT_COMMIT_SHA

    if [ "$pull_required" = "true" ] &&
        ! compose_command pull; then
        return 1
    fi

    if ! compose_command up \
        --detach \
        --remove-orphans \
        --pull never \
        --wait \
        --wait-timeout 120; then
        return 1
    fi

    if ! verify_release "$candidate_sha"; then
        return 1
    fi
}

if ! compose_command config --quiet; then
    write_result \
        "configuration_failed" \
        "not_attempted" \
        "$PREVIOUS_SHA"

    printf 'DEPLOYMENT_RESULT=configuration_failed\n' >&2
    exit 1
fi

if ! capture_previous_release; then
    write_result \
        "previous_release_invalid" \
        "not_attempted" \
        ""

    printf 'DEPLOYMENT_RESULT=previous_release_invalid\n' >&2
    exit 1
fi

if deploy_sha "$TARGET_SHA" "true"; then
    write_result \
        "deployed" \
        "not_required" \
        "$TARGET_SHA"

    printf 'DEPLOYMENT_RESULT=deployed ROLLBACK=not_required\n'
    exit 0
fi

printf 'DEPLOYMENT_RESULT=failed ROLLBACK=required\n' >&2

if [ -z "$PREVIOUS_SHA" ]; then
    compose_command down \
        --remove-orphans \
        >/dev/null 2>&1 ||
        true

    write_result \
        "deployment_failed" \
        "unavailable" \
        ""

    printf 'ROLLBACK_RESULT=unavailable\n' >&2
    exit 1
fi

if deploy_sha "$PREVIOUS_SHA" "false"; then
    write_result \
        "deployment_failed_rolled_back" \
        "succeeded" \
        "$PREVIOUS_SHA"

    printf 'ROLLBACK_RESULT=succeeded\n' >&2
    exit 1
fi

write_result \
    "rollback_failed" \
    "failed" \
    ""

printf 'ROLLBACK_RESULT=failed\n' >&2
exit 1
