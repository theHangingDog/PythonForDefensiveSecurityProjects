# jobs.py

import os
from datetime import datetime
from telegram.ext import ContextTypes
from utils import fetch_daily_feeds, parse_feed_data
from config import logger

async def push_feeds_to_users(app, normalized_data, limit=10):
    try:
        if not normalized_data:
            logger.warning("No feeds available to push")
            return
        chat_id = os.getenv("TELEGRAM_CHAT_ID")
        if not chat_id:
            logger.error("No TELEGRAM_CHAT_ID found in .env - cannot push feeds") # Improved logging
            return
        # Prepare message
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        message = f"*Latest Threat Feeds* ({timestamp}):\n\n"
        for item in normalized_data[:limit]:
            indicator = item.get("indicator", "N/A")
            source = item.get("source", "Unknown")
            ioc_type = item.get("type", "unknown")
            message += f"• `{indicator}` \n _{ioc_type}_ from *{source}*\n"
        # Send message
        await app.bot.send_message(
            chat_id=chat_id,
            text=message,
            parse_mode="Markdown"
        )
        logger.info(f"Pushed {min(limit, len(normalized_data))} indicators to chat {chat_id}")
    except Exception as e:
        logger.exception(f"Error in push_feeds_to_users: {e}")

async def periodic_feeds_job(context: ContextTypes.DEFAULT_TYPE):
    """Fetches and pushes new feeds periodically. This is a scheduled job."""
    logger.info("Running periodic feeds job...")
    feeds = fetch_daily_feeds()
    normalized_data = parse_feed_data(feeds)
   
    # Ensure you have set TELEGRAM_CHAT_ID in your .env file
    if normalized_data and os.getenv("TELEGRAM_CHAT_ID"):
        await push_feeds_to_users(context.application, normalized_data)
    else:
        logger.warning("No feeds to push or TELEGRAM_CHAT_ID not set.")