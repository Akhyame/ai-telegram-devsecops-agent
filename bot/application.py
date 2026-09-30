"""Offline-safe Telegram application factory."""

from telegram import Update
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    MessageHandler,
    TypeHandler,
    filters,
)

from bot.config import get_bot_settings
from bot.deploy_handlers import (
    DEPLOY_CALLBACK_PATTERN,
    deploy_confirmation_handler,
    deploy_handler,
    deploy_staging_handler,
)
from bot.error_handling import (
    error_handler,
    unknown_command_handler,
)
from bot.explain_handlers import (
    explain_handler,
    explain_security_handler,
)
from bot.handlers import (
    help_handler,
    logs_handler,
    start_handler,
    status_handler,
)
from bot.pipeline_action_handlers import (
    CANCEL_PIPELINE_CALLBACK_PATTERN,
    RETRY_PIPELINE_CALLBACK_PATTERN,
    cancel_pipeline_confirmation_handler,
    cancel_pipeline_handler,
    retry_pipeline_confirmation_handler,
    retry_pipeline_handler,
)
from bot.rbac import BotCommand
from bot.run_pipeline_handlers import (
    RUN_PIPELINE_CALLBACK_PATTERN,
    run_pipeline_confirmation_handler,
    run_pipeline_handler,
)
from bot.scan_handlers import (
    SCAN_CALLBACK_PATTERN,
    scan_confirmation_handler,
    scan_handler,
)
from bot.telegram_rate_limit import telegram_rate_limit_handler


def build_application() -> Application:
    """Build the Telegram application without starting network activity."""

    settings = get_bot_settings()
    application = Application.builder().token(settings.token.get_secret_value()).build()

    application.add_handler(
        TypeHandler(Update, telegram_rate_limit_handler),
        group=-1,
    )

    application.add_handler(
        CommandHandler(
            BotCommand.START.value,
            start_handler,
        )
    )
    application.add_handler(
        CommandHandler(
            BotCommand.HELP.value,
            help_handler,
        )
    )
    application.add_handler(
        CommandHandler(
            BotCommand.STATUS.value,
            status_handler,
        )
    )
    application.add_handler(
        CommandHandler(
            BotCommand.LOGS.value,
            logs_handler,
        )
    )
    application.add_handler(
        CommandHandler(
            BotCommand.EXPLAIN.value,
            explain_handler,
        )
    )
    application.add_handler(
        CommandHandler(
            BotCommand.EXPLAIN_SECURITY.value,
            explain_security_handler,
        )
    )
    application.add_handler(
        CommandHandler(
            BotCommand.RUN_PIPELINE.value,
            run_pipeline_handler,
        )
    )
    application.add_handler(
        CommandHandler(
            BotCommand.RETRY_PIPELINE.value,
            retry_pipeline_handler,
        )
    )
    application.add_handler(
        CommandHandler(
            BotCommand.CANCEL_PIPELINE.value,
            cancel_pipeline_handler,
        )
    )
    application.add_handler(
        CommandHandler(
            BotCommand.SCAN.value,
            scan_handler,
        )
    )
    application.add_handler(
        CommandHandler(
            BotCommand.DEPLOY.value,
            deploy_handler,
        )
    )
    application.add_handler(
        CommandHandler(
            "deploy_staging",
            deploy_staging_handler,
        )
    )
    application.add_handler(
        CallbackQueryHandler(
            run_pipeline_confirmation_handler,
            pattern=RUN_PIPELINE_CALLBACK_PATTERN,
        )
    )
    application.add_handler(
        CallbackQueryHandler(
            retry_pipeline_confirmation_handler,
            pattern=RETRY_PIPELINE_CALLBACK_PATTERN,
        )
    )
    application.add_handler(
        CallbackQueryHandler(
            cancel_pipeline_confirmation_handler,
            pattern=CANCEL_PIPELINE_CALLBACK_PATTERN,
        )
    )
    application.add_handler(
        CallbackQueryHandler(
            scan_confirmation_handler,
            pattern=SCAN_CALLBACK_PATTERN,
        )
    )
    application.add_handler(
        CallbackQueryHandler(
            deploy_confirmation_handler,
            pattern=DEPLOY_CALLBACK_PATTERN,
        )
    )
    application.add_handler(
        MessageHandler(
            filters.COMMAND,
            unknown_command_handler,
        )
    )
    application.add_error_handler(
        error_handler,
        block=True,
    )

    return application
