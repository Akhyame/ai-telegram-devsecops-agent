"""Fresh, bounded, and replay-resistant action confirmations."""

import hashlib
import re
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum

from deployment.models import DeploymentEnvironment

CONFIRMATION_TTL_SECONDS = 120.0
MAX_PENDING_CONFIRMATIONS = 1_024

_MAX_IDENTIFIER = (2**63) - 1
_TOKEN_PATTERN = re.compile(r"\A[A-Za-z0-9_-]{32}\Z")
_SAFE_REF_PATTERN = re.compile(r"\A[A-Za-z0-9](?:[A-Za-z0-9._/-]{0,253}[A-Za-z0-9])?\Z")
_TOKEN_GENERATION_ATTEMPTS = 4


class ActionKind(StrEnum):
    """Mutating actions requiring deterministic confirmation."""

    RUN_PIPELINE = "run_pipeline"
    CANCEL_PIPELINE = "cancel_pipeline"
    RETRY_PIPELINE = "retry_pipeline"
    SCAN = "scan"
    DEPLOY = "deploy"


class ActionConfirmationError(RuntimeError):
    """Static failure for invalid confirmation state or input."""


@dataclass(frozen=True, slots=True)
class ActionTarget:
    """Validated project, ref, and optional pipeline target."""

    project_id: int
    ref: str
    pipeline_id: int | None = None
    environment: DeploymentEnvironment | None = None

    def __post_init__(self) -> None:
        if not _is_positive_identifier(self.project_id):
            raise ActionConfirmationError("Action confirmation failed.")

        unsafe_sequences = (
            "..",
            "//",
            "@{",
        )

        if (
            not isinstance(self.ref, str)
            or _SAFE_REF_PATTERN.fullmatch(self.ref) is None
            or any(sequence in self.ref for sequence in unsafe_sequences)
            or self.ref.endswith(".lock")
        ):
            raise ActionConfirmationError("Action confirmation failed.")

        if self.pipeline_id is not None and not _is_positive_identifier(self.pipeline_id):
            raise ActionConfirmationError("Action confirmation failed.")

        if self.environment is not None and not isinstance(
            self.environment,
            DeploymentEnvironment,
        ):
            raise ActionConfirmationError("Action confirmation failed.")


@dataclass(frozen=True, slots=True)
class _PendingConfirmation:
    user_id: int
    action: ActionKind
    target: ActionTarget
    expires_at: float


class ActionConfirmationStore:
    """Thread-safe one-time confirmation store using token digests."""

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.monotonic,
        token_factory: Callable[[], str] = (lambda: secrets.token_urlsafe(24)),
    ) -> None:
        self._clock = clock
        self._token_factory = token_factory
        self._pending: dict[
            bytes,
            _PendingConfirmation,
        ] = {}
        self._lock = threading.RLock()

    def issue(
        self,
        *,
        user_id: int,
        action: ActionKind,
        target: ActionTarget,
    ) -> str:
        """Issue one fresh token bound to an exact action intent."""

        if not self._valid_binding(
            user_id=user_id,
            action=action,
            target=target,
        ):
            raise ActionConfirmationError("Action confirmation failed.")

        now = self._clock()

        with self._lock:
            self._prune_expired(now)

            for _attempt in range(_TOKEN_GENERATION_ATTEMPTS):
                try:
                    token = self._token_factory()
                except Exception as exc:
                    raise ActionConfirmationError("Action confirmation failed.") from exc

                if not isinstance(token, str) or _TOKEN_PATTERN.fullmatch(token) is None:
                    raise ActionConfirmationError("Action confirmation failed.")

                digest = self._digest(token)

                if digest in self._pending:
                    continue

                if len(self._pending) >= MAX_PENDING_CONFIRMATIONS:
                    self._evict_oldest()

                self._pending[digest] = _PendingConfirmation(
                    user_id=user_id,
                    action=action,
                    target=target,
                    expires_at=(now + CONFIRMATION_TTL_SECONDS),
                )
                return token

        raise ActionConfirmationError("Action confirmation failed.")

    def claim(
        self,
        token: object,
        *,
        user_id: int,
        action: ActionKind,
        target: ActionTarget,
    ) -> bool:
        """Atomically consume one matching unexpired token."""

        if (
            not isinstance(token, str)
            or _TOKEN_PATTERN.fullmatch(token) is None
            or not self._valid_binding(
                user_id=user_id,
                action=action,
                target=target,
            )
        ):
            return False

        digest = self._digest(token)
        now = self._clock()

        with self._lock:
            self._prune_expired(now)
            pending = self._pending.get(digest)

            if pending is None:
                return False

            if (
                pending.user_id != user_id
                or pending.action is not action
                or pending.target != target
            ):
                return False

            self._pending.pop(digest)
            return True

    @property
    def pending_count(self) -> int:
        """Return the bounded count after removing expired entries."""

        now = self._clock()

        with self._lock:
            self._prune_expired(now)
            return len(self._pending)

    def clear(self) -> None:
        """Clear process-local state for controlled shutdown/tests."""

        with self._lock:
            self._pending.clear()

    def __repr__(self) -> str:
        return f"ActionConfirmationStore(pending_count={self.pending_count})"

    @staticmethod
    def _valid_binding(
        *,
        user_id: object,
        action: object,
        target: object,
    ) -> bool:
        if (
            not _is_positive_identifier(user_id)
            or not isinstance(action, ActionKind)
            or not isinstance(target, ActionTarget)
        ):
            return False

        requires_pipeline = action in {
            ActionKind.CANCEL_PIPELINE,
            ActionKind.RETRY_PIPELINE,
        }

        if requires_pipeline:
            return target.pipeline_id is not None and target.environment is None

        if action is ActionKind.DEPLOY:
            return target.pipeline_id is None and target.environment is not None

        return target.pipeline_id is None and target.environment is None

    @staticmethod
    def _digest(token: str) -> bytes:
        return hashlib.sha256(
            token.encode("ascii"),
        ).digest()

    def _prune_expired(self, now: float) -> None:
        expired = tuple(
            digest for digest, pending in self._pending.items() if pending.expires_at <= now
        )

        for digest in expired:
            self._pending.pop(digest, None)

    def _evict_oldest(self) -> None:
        digest = min(
            self._pending,
            key=lambda item: (
                self._pending[item].expires_at,
                item,
            ),
        )
        self._pending.pop(digest)


def _is_positive_identifier(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 < value <= _MAX_IDENTIFIER


action_confirmation_store = ActionConfirmationStore()
