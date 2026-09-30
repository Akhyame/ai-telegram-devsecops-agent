from bot.rate_limit import BoundedRateLimiter


class FakeClock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def test_rate_limiter_allows_requests_within_limit():
    clock = FakeClock()
    limiter = BoundedRateLimiter(
        maximum_requests=3,
        window_seconds=60,
        clock=clock,
    )

    assert limiter.allow("user:1") is True
    assert limiter.allow("user:1") is True
    assert limiter.allow("user:1") is True
    assert limiter.allow("user:1") is False


def test_rate_limiter_isolated_per_identity():
    clock = FakeClock()
    limiter = BoundedRateLimiter(
        maximum_requests=1,
        window_seconds=60,
        clock=clock,
    )

    assert limiter.allow("user:1") is True
    assert limiter.allow("user:1") is False
    assert limiter.allow("user:2") is True


def test_rate_limiter_resets_after_window():
    clock = FakeClock()
    limiter = BoundedRateLimiter(
        maximum_requests=1,
        window_seconds=10,
        clock=clock,
    )

    assert limiter.allow("user:1") is True
    assert limiter.allow("user:1") is False

    clock.advance(10)

    assert limiter.allow("user:1") is True


def test_rate_limiter_rejects_invalid_identity():
    limiter = BoundedRateLimiter(
        maximum_requests=1,
        window_seconds=60,
    )

    assert limiter.allow("") is False
    assert limiter.allow("x" * 129) is False


def test_rate_limiter_configuration_fails_closed():
    for kwargs in (
        {"maximum_requests": 0, "window_seconds": 60},
        {"maximum_requests": 1, "window_seconds": 0},
        {
            "maximum_requests": 1,
            "window_seconds": 60,
            "maximum_entries": 0,
        },
    ):
        try:
            BoundedRateLimiter(**kwargs)
        except ValueError:
            pass
        else:
            raise AssertionError("Invalid limiter configuration was accepted.")


def test_rate_limiter_state_is_bounded():
    clock = FakeClock()
    limiter = BoundedRateLimiter(
        maximum_requests=1,
        window_seconds=60,
        maximum_entries=2,
        clock=clock,
    )

    assert limiter.allow("user:1") is True

    clock.advance(1)
    assert limiter.allow("user:2") is True

    clock.advance(1)
    assert limiter.allow("user:3") is True

    assert limiter.entry_count == 2


def test_rate_limiter_prunes_expired_state():
    clock = FakeClock()
    limiter = BoundedRateLimiter(
        maximum_requests=1,
        window_seconds=5,
        maximum_entries=10,
        clock=clock,
    )

    assert limiter.allow("user:1") is True
    assert limiter.entry_count == 1

    clock.advance(5)

    assert limiter.entry_count == 0
