# main.py

import asyncio
import nest_asyncio
from keep_alive import keep_alive
from telegram import BotCommand
from telegram.ext import Application, CommandHandler, ContextTypes
from config import BOT_TOKEN, logger
from database import init_db
from handlers import (
    start_handler,
    check_ip_handler,
    checkdomain_handler,
    checkhash_handler,
    feeds_handler,
    help_handler,
    correlate_handler,
    stats_handler
)
from jobs import periodic_feeds_job

keep_alive()
async def start_bot():
    try:
        if not BOT_TOKEN:
            raise ValueError("Telegram Bot Token is missing in .env file.")
        app = Application.builder().token(BOT_TOKEN).build()
        await register_commands(app)
        # Schedule the periodic job for feeds
        job_queue = app.job_queue
        # Runs the job every 2 hours (7200s), and the first run is 10s after bot starts.
        job_queue.run_repeating(periodic_feeds_job, interval=7200, first=10)
        logger.info("Bot started successfully.")
        await app.run_polling() # Fixed typo: await app.run_polling()
    except Exception as e:
        logger.exception(f"Error starting bot: {e}") # Use logger.exception for traceback

async def register_commands(app):
    try:
        commands = [
            BotCommand("start", "Start the bot."),
            BotCommand("checkip", "Check reputation of an IP."),
            BotCommand("checkdomain", "Check reputation of a domain."),
            BotCommand("checkhash", "Check reputation of a hash."),
            BotCommand("correlate", "Correlate any IOC (IP, domain, hash)."),
            BotCommand("feeds", "Get latest threat intel feeds."),
            BotCommand("stats", "Show your usage statistics."),
            BotCommand("help", "Lists all available commands.")
        ]
        await app.bot.set_my_commands(commands)
        app.add_handler(CommandHandler("start", start_handler))
        app.add_handler(CommandHandler("checkip", check_ip_handler))
        app.add_handler(CommandHandler("checkdomain", checkdomain_handler))
        app.add_handler(CommandHandler("checkhash", checkhash_handler))
        app.add_handler(CommandHandler("feeds", feeds_handler))
        app.add_handler(CommandHandler("help", help_handler))
        app.add_handler(CommandHandler("correlate", correlate_handler))
        app.add_handler(CommandHandler("stats", stats_handler))
        logger.info("Commands registered successfully.")
    except Exception as e:
        logger.exception(f"Error registering commands: {e}") # Use logger.exception

if __name__ == "__main__":
    init_db() # Initialize the database on startup
    nest_asyncio.apply() # Add this line to allow nested event loops
    asyncio.run(start_bot())