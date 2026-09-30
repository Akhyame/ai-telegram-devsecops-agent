"""Controlled runtime boundary for the Telegram bot."""

import logging

from bot.application import build_application
from bot.config import BotConfigurationError

ALLOWED_UPDATE_TYPES = ("message", "callback_query")

EXIT_SUCCESS = 0
EXIT_RUNTIME_FAILURE = 1
EXIT_CONFIGURATION_FAILURE = 2

CONFIGURATION_FAILURE_LOG_MESSAGE = "Telegram runtime configuration failed."
RUNTIME_FAILURE_LOG_MESSAGE = "Telegram runtime failed."

_LOGGER = logging.getLogger(__name__)


def run_bot() -> None:
    """Build and run the bot with restricted polling behavior."""

    application = build_application()
    application.run_polling(
        allowed_updates=ALLOWED_UPDATE_TYPES,
        bootstrap_retries=0,
        drop_pending_updates=True,
        close_loop=True,
        stop_signals=None,
    )


def main() -> int:
    """Run the bot and return a controlled process exit code."""

    try:
        run_bot()
    except BotConfigurationError:
        _LOGGER.error(CONFIGURATION_FAILURE_LOG_MESSAGE)
        return EXIT_CONFIGURATION_FAILURE
    except Exception:
        _LOGGER.error(RUNTIME_FAILURE_LOG_MESSAGE)
        return EXIT_RUNTIME_FAILURE

    return EXIT_SUCCESS
