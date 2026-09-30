"""Offline tests for fresh one-time action confirmations."""

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

import pytest

from bot.action_confirmation import (
    CONFIRMATION_TTL_SECONDS,
    MAX_PENDING_CONFIRMATIONS,
    ActionConfirmationError,
    ActionConfirmationStore,
    ActionKind,
    ActionTarget,
)

_USER_ID = 101
_PROJECT_ID = 123456
_REF = "main"


class _Clock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value


def _token(value: int) -> str:
    return f"{value:032d}"


def _token_factory(
    values: list[str],
) -> Callable[[], str]:
    iterator = iter(values)
    return lambda: next(iterator)


def _target(
    *,
    pipeline_id: int | None = None,
    ref: str = _REF,
) -> ActionTarget:
    return ActionTarget(
        project_id=_PROJECT_ID,
        ref=ref,
        pipeline_id=pipeline_id,
    )


def test_security_constants_are_fixed() -> None:
    assert CONFIRMATION_TTL_SECONDS == 120.0
    assert MAX_PENDING_CONFIRMATIONS == 1_024


@pytest.mark.parametrize(
    "action",
    (
        ActionKind.RUN_PIPELINE,
        ActionKind.SCAN,
    ),
)
def test_ref_action_confirmation_is_single_use(
    action: ActionKind,
) -> None:
    store = ActionConfirmationStore(
        token_factory=lambda: _token(1),
    )
    target = _target()

    token = store.issue(
        user_id=_USER_ID,
        action=action,
        target=target,
    )

    assert token == _token(1)
    assert store.pending_count == 1
    assert store.claim(
        token,
        user_id=_USER_ID,
        action=action,
        target=target,
    )
    assert not store.claim(
        token,
        user_id=_USER_ID,
        action=action,
        target=target,
    )
    assert store.pending_count == 0


@pytest.mark.parametrize(
    "action",
    (
        ActionKind.CANCEL_PIPELINE,
        ActionKind.RETRY_PIPELINE,
    ),
)
def test_pipeline_action_confirmation_is_single_use(
    action: ActionKind,
) -> None:
    store = ActionConfirmationStore(
        token_factory=lambda: _token(2),
    )
    target = _target(pipeline_id=987654)

    token = store.issue(
        user_id=_USER_ID,
        action=action,
        target=target,
    )

    assert store.claim(
        token,
        user_id=_USER_ID,
        action=action,
        target=target,
    )
    assert not store.claim(
        token,
        user_id=_USER_ID,
        action=action,
        target=target,
    )


def test_confirmation_is_bound_to_user_action_and_target() -> None:
    store = ActionConfirmationStore(
        token_factory=lambda: _token(3),
    )
    target = _target()

    token = store.issue(
        user_id=_USER_ID,
        action=ActionKind.RUN_PIPELINE,
        target=target,
    )

    assert not store.claim(
        token,
        user_id=202,
        action=ActionKind.RUN_PIPELINE,
        target=target,
    )
    assert not store.claim(
        token,
        user_id=_USER_ID,
        action=ActionKind.SCAN,
        target=target,
    )
    assert not store.claim(
        token,
        user_id=_USER_ID,
        action=ActionKind.RUN_PIPELINE,
        target=_target(ref="release"),
    )
    assert store.claim(
        token,
        user_id=_USER_ID,
        action=ActionKind.RUN_PIPELINE,
        target=target,
    )


def test_confirmation_expires_at_exact_ttl_boundary() -> None:
    clock = _Clock()
    store = ActionConfirmationStore(
        clock=clock,
        token_factory=lambda: _token(4),
    )
    target = _target()

    token = store.issue(
        user_id=_USER_ID,
        action=ActionKind.RUN_PIPELINE,
        target=target,
    )

    clock.value = CONFIRMATION_TTL_SECONDS

    assert not store.claim(
        token,
        user_id=_USER_ID,
        action=ActionKind.RUN_PIPELINE,
        target=target,
    )
    assert store.pending_count == 0


def test_confirmation_is_valid_immediately_before_expiry() -> None:
    clock = _Clock()
    store = ActionConfirmationStore(
        clock=clock,
        token_factory=lambda: _token(5),
    )
    target = _target()

    token = store.issue(
        user_id=_USER_ID,
        action=ActionKind.RUN_PIPELINE,
        target=target,
    )

    clock.value = CONFIRMATION_TTL_SECONDS - 0.001

    assert store.claim(
        token,
        user_id=_USER_ID,
        action=ActionKind.RUN_PIPELINE,
        target=target,
    )


@pytest.mark.parametrize(
    "invalid_token",
    (
        None,
        123,
        "",
        "A" * 31,
        "A" * 33,
        "A" * 31 + "!",
        "A" * 31 + "\n",
    ),
)
def test_invalid_confirmation_tokens_fail_closed(
    invalid_token: object,
) -> None:
    store = ActionConfirmationStore()

    assert not store.claim(
        invalid_token,
        user_id=_USER_ID,
        action=ActionKind.RUN_PIPELINE,
        target=_target(),
    )


@pytest.mark.parametrize(
    "invalid_user_id",
    (
        True,
        0,
        -1,
        2**63,
    ),
)
def test_invalid_user_id_is_rejected(
    invalid_user_id: object,
) -> None:
    store = ActionConfirmationStore()

    with pytest.raises(
        ActionConfirmationError,
        match=r"\AAction confirmation failed\.\Z",
    ):
        store.issue(
            user_id=invalid_user_id,
            action=ActionKind.RUN_PIPELINE,
            target=_target(),
        )


@pytest.mark.parametrize(
    "invalid_ref",
    (
        "../main",
        "main?token=secret",
        "main branch",
        "feature//unsafe",
        "refs/heads/test.lock",
    ),
)
def test_invalid_target_ref_is_rejected(
    invalid_ref: str,
) -> None:
    with pytest.raises(
        ActionConfirmationError,
        match=r"\AAction confirmation failed\.\Z",
    ):
        _target(ref=invalid_ref)


@pytest.mark.parametrize(
    "invalid_identifier",
    (
        True,
        0,
        -1,
        2**63,
    ),
)
def test_invalid_target_identifiers_are_rejected(
    invalid_identifier: object,
) -> None:
    with pytest.raises(ActionConfirmationError):
        ActionTarget(
            project_id=invalid_identifier,
            ref=_REF,
        )

    with pytest.raises(ActionConfirmationError):
        ActionTarget(
            project_id=_PROJECT_ID,
            ref=_REF,
            pipeline_id=invalid_identifier,
        )


@pytest.mark.parametrize(
    ("action", "target"),
    (
        (
            ActionKind.RUN_PIPELINE,
            ActionTarget(
                project_id=_PROJECT_ID,
                ref=_REF,
                pipeline_id=987654,
            ),
        ),
        (
            ActionKind.SCAN,
            ActionTarget(
                project_id=_PROJECT_ID,
                ref=_REF,
                pipeline_id=987654,
            ),
        ),
        (
            ActionKind.CANCEL_PIPELINE,
            ActionTarget(
                project_id=_PROJECT_ID,
                ref=_REF,
            ),
        ),
        (
            ActionKind.RETRY_PIPELINE,
            ActionTarget(
                project_id=_PROJECT_ID,
                ref=_REF,
            ),
        ),
    ),
)
def test_action_target_shape_mismatch_is_rejected(
    action: ActionKind,
    target: ActionTarget,
) -> None:
    store = ActionConfirmationStore()

    with pytest.raises(ActionConfirmationError):
        store.issue(
            user_id=_USER_ID,
            action=action,
            target=target,
        )


def test_wrong_binding_does_not_consume_confirmation() -> None:
    store = ActionConfirmationStore(
        token_factory=lambda: _token(6),
    )
    target = _target(pipeline_id=987654)

    token = store.issue(
        user_id=_USER_ID,
        action=ActionKind.CANCEL_PIPELINE,
        target=target,
    )

    assert not store.claim(
        token,
        user_id=202,
        action=ActionKind.CANCEL_PIPELINE,
        target=target,
    )
    assert store.pending_count == 1
    assert store.claim(
        token,
        user_id=_USER_ID,
        action=ActionKind.CANCEL_PIPELINE,
        target=target,
    )


def test_only_one_concurrent_claim_can_succeed() -> None:
    store = ActionConfirmationStore(
        token_factory=lambda: _token(7),
    )
    target = _target()
    token = store.issue(
        user_id=_USER_ID,
        action=ActionKind.RUN_PIPELINE,
        target=target,
    )

    def claim() -> bool:
        return store.claim(
            token,
            user_id=_USER_ID,
            action=ActionKind.RUN_PIPELINE,
            target=target,
        )

    with ThreadPoolExecutor(max_workers=16) as executor:
        results = list(executor.map(lambda _item: claim(), range(64)))

    assert sum(results) == 1


def test_store_is_bounded_and_evicts_oldest_entry() -> None:
    clock = _Clock()
    values = [
        _token(value)
        for value in range(
            1,
            MAX_PENDING_CONFIRMATIONS + 2,
        )
    ]
    store = ActionConfirmationStore(
        clock=clock,
        token_factory=_token_factory(values),
    )
    target = _target()

    first_token = store.issue(
        user_id=_USER_ID,
        action=ActionKind.RUN_PIPELINE,
        target=target,
    )

    for value in range(
        2,
        MAX_PENDING_CONFIRMATIONS + 2,
    ):
        clock.value = value / 1_000
        store.issue(
            user_id=_USER_ID,
            action=ActionKind.RUN_PIPELINE,
            target=target,
        )

    assert store.pending_count == MAX_PENDING_CONFIRMATIONS
    assert not store.claim(
        first_token,
        user_id=_USER_ID,
        action=ActionKind.RUN_PIPELINE,
        target=target,
    )
    assert store.claim(
        values[-1],
        user_id=_USER_ID,
        action=ActionKind.RUN_PIPELINE,
        target=target,
    )


def test_raw_confirmation_token_is_not_in_store_repr() -> None:
    token = _token(8)
    store = ActionConfirmationStore(
        token_factory=lambda: token,
    )

    store.issue(
        user_id=_USER_ID,
        action=ActionKind.RUN_PIPELINE,
        target=_target(),
    )

    assert token not in repr(store)


def test_token_collision_retries_with_fresh_value() -> None:
    duplicate = _token(9)
    fresh = _token(10)
    store = ActionConfirmationStore(
        token_factory=_token_factory(
            [
                duplicate,
                duplicate,
                fresh,
            ]
        ),
    )

    first = store.issue(
        user_id=_USER_ID,
        action=ActionKind.RUN_PIPELINE,
        target=_target(),
    )
    second = store.issue(
        user_id=_USER_ID,
        action=ActionKind.RUN_PIPELINE,
        target=_target(),
    )

    assert first == duplicate
    assert second == fresh


def test_collision_exhaustion_is_static_and_redacted() -> None:
    token = _token(11)
    store = ActionConfirmationStore(
        token_factory=lambda: token,
    )

    store.issue(
        user_id=_USER_ID,
        action=ActionKind.RUN_PIPELINE,
        target=_target(),
    )

    with pytest.raises(
        ActionConfirmationError,
        match=r"\AAction confirmation failed\.\Z",
    ) as error:
        store.issue(
            user_id=_USER_ID,
            action=ActionKind.RUN_PIPELINE,
            target=_target(),
        )

    assert token not in str(error.value)


def test_invalid_token_factory_output_is_rejected() -> None:
    sensitive_value = "DO-NOT-LEAK invalid token"
    store = ActionConfirmationStore(
        token_factory=lambda: sensitive_value,
    )

    with pytest.raises(
        ActionConfirmationError,
        match=r"\AAction confirmation failed\.\Z",
    ) as error:
        store.issue(
            user_id=_USER_ID,
            action=ActionKind.RUN_PIPELINE,
            target=_target(),
        )

    assert sensitive_value not in str(error.value)


def test_clear_removes_all_pending_confirmations() -> None:
    store = ActionConfirmationStore(
        token_factory=lambda: _token(12),
    )

    store.issue(
        user_id=_USER_ID,
        action=ActionKind.RUN_PIPELINE,
        target=_target(),
    )
    store.clear()

    assert store.pending_count == 0
