# handlers.py

import re
import io
import csv
from datetime import datetime
from telegram import Update
from telegram.ext import ContextTypes
from utils import (  # Import utility functions
    check_ip_reputation,
    check_domain_reputation,
    check_hash_reputation,
    detect_ioc_type,
    fetch_daily_feeds,
    parse_feed_data,
    ioc_correlation
)
from database import store_user_logs  # Import DB functions
from config import logger  # Import logger from config

async def start_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle the /start command"""
    welcome_message = (
        "🛡️ *Threat Intelligence Bot* 🛡️\n\n"
        "I can help you analyze potential cybersecurity threats!\n\n"
        "*Available Commands:*\n"
        "• /checkip <IP> - Check IP reputation\n"
        "• /checkdomain <domain> - Check domain reputation\n"
        "• /checkhash <hash> - Check file hash reputation\n"
        "• /correlate <indicator> - Correlate any IOC (IP, domain, hash)\n" # Added
        "• /feeds - Get latest threat intelligence feeds\n"
        "• /stats - Show your usage statistics\n" # Added
        "• /help - Show detailed help information\n\n"
        "Use /help for more detailed information about each command."
    )
   
    await update.message.reply_text(welcome_message, parse_mode="Markdown")

async def check_ip_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle the /checkip command"""
    if not context.args:
        await update.message.reply_text(
            "Please provide an IP address to check.\n\n"
            "Usage: `/checkip 192.168.1.1`",
            parse_mode="Markdown"
        )
        return
   
    ip_address = context.args[0]
   
    # Validate IP format
    ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
    if not re.match(ip_pattern, ip_address):
        await update.message.reply_text(
            "❌ Invalid IP address format. Please provide a valid IPv4 address.\n\n"
            "Example: `/checkip 8.8.8.8`",
            parse_mode="Markdown"
        )
        return
   
    # Send processing message
    processing_msg = await update.message.reply_text(
        f"🔍 Checking IP reputation for `{ip_address}`...",
        parse_mode="Markdown"
    )
   
    try:
        # Check IP reputation
        result = check_ip_reputation(ip_address)
       
        # Store in database
        store_user_logs(update.effective_user.id, f"checkip {ip_address}", result)
       
        # Format and send results
        if result:
            message = f"*IP Reputation Results for {ip_address}:*\n\n"
           
            for source, data in result.items():
                message += f"*{source}:*\n"
               
                if isinstance(data, dict):
                    if "error" in data:
                        message += f" ❌ {data['error']}\n"
                    else:
                        # Extract relevant info based on source
                        if source == "VirusTotal" and "data" in data:
                            stats = data["data"].get("attributes", {}).get("last_analysis_stats", {})
                            message += f" ✅ Malicious: {stats.get('malicious', 'N/A')}\n"
                            message += f" ✅ Suspicious: {stats.get('suspicious', 'N/A')}\n"
                            message += f" ✅ Clean: {stats.get('harmless', 'N/A')}\n"
                            message += f" ✅ Undetected: {stats.get('undetected', 'N/A')}\n"
                        elif source == "AlienVault OTX" and "pulse_info" in data:
                            pulses = data["pulse_info"].get("count", 0)
                            message += f" 📊 Found in {pulses} threat intelligence pulses\n"
                        elif "data" in data:
                            # For other sources with data
                            message += f" ℹ️ Data available\n"
                        else:
                            message += f" ℹ️ No detailed information available\n"
                else:
                    # Truncate long text responses
                    truncated_text = str(data)[:100] + "..." if len(str(data)) > 100 else str(data)
                    message += f" 📝 {truncated_text}\n"
               
                message += "\n"
           
            await context.bot.edit_message_text(
                chat_id=update.effective_chat.id,
                message_id=processing_msg.message_id,
                text=message,
                parse_mode="Markdown"
            )
        else:
            await context.bot.edit_message_text(
                chat_id=update.effective_chat.id,
                message_id=processing_msg.message_id,
                text=f"❌ Could not retrieve reputation data for `{ip_address}`",
                parse_mode="Markdown"
            )
           
    except Exception as e:
        logger.error(f"Error in check_ip_handler: {e}")
        await context.bot.edit_message_text(
            chat_id=update.effective_chat.id,
            message_id=processing_msg.message_id,
            text=f"❌ An error occurred while checking IP reputation: {str(e)}"
        )

async def checkdomain_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle the /checkdomain command"""
    if not context.args:
        await update.message.reply_text(
            "Please provide a domain to check.\n\n"
            "Usage: `/checkdomain example.com`",
            parse_mode="Markdown"
        )
        return
   
    domain = context.args[0]
   
    # Validate domain format
    domain_pattern = r"^[\w.-]+\.[a-zA-Z]{2,}$"
    if not re.match(domain_pattern, domain):
        await update.message.reply_text(
            "❌ Invalid domain format. Please provide a valid domain name.\n\n"
            "Example: `/checkdomain google.com`",
            parse_mode="Markdown"
        )
        return
   
    # Send processing message
    processing_msg = await update.message.reply_text(
        f"🔍 Checking domain reputation for `{domain}`...",
        parse_mode="Markdown"
    )
   
    try:
        # Check domain reputation
        result = check_domain_reputation(domain)
       
        # Store in database
        store_user_logs(update.effective_user.id, f"checkdomain {domain}", result)
       
        # Format and send results
        if result:
            message = f"*Domain Reputation Results for {domain}:*\n\n"
           
            for source, data in result.items():
                message += f"*{source}:*\n"
               
                if isinstance(data, dict):
                    if "error" in data:
                        message += f" ❌ {data['error']}\n"
                    else:
                        # Extract relevant info based on source
                        if source == "VirusTotal" and "data" in data:
                            stats = data["data"].get("attributes", {}).get("last_analysis_stats", {})
                            message += f" ✅ Malicious: {stats.get('malicious', 'N/A')}\n"
                            message += f" ✅ Suspicious: {stats.get('suspicious', 'N/A')}\n"
                            message += f" ✅ Clean: {stats.get('harmless', 'N/A')}\n"
                            message += f" ✅ Undetected: {stats.get('undetected', 'N/A')}\n"
                        elif source == "AlienVault OTX" and "pulse_info" in data:
                            pulses = data["pulse_info"].get("count", 0)
                            message += f" 📊 Found in {pulses} threat intelligence pulses\n"
                        elif source == "URLhaus":
                            if "blacklists" in data:
                                blacklists = data.get("blacklists", {})
                                if "urlhaus" in blacklists and blacklists["urlhaus"]:
                                    message += f" ⚠️ Listed in URLhaus blacklist\n"
                                else:
                                    message += f" ✅ Not found in URLhaus blacklist\n"
                            else:
                                message += f" ℹ️ No blacklist data available\n"
                        else:
                            message += f" ℹ️ Data available\n"
                else:
                    message += f" 📝 {str(data)[:100]}...\n"
               
                message += "\n"
           
            await context.bot.edit_message_text(
                chat_id=update.effective_chat.id,
                message_id=processing_msg.message_id,
                text=message,
                parse_mode="Markdown"
            )
        else:
            await context.bot.edit_message_text(
                chat_id=update.effective_chat.id,
                message_id=processing_msg.message_id,
                text=f"❌ Could not retrieve reputation data for `{domain}`",
                parse_mode="Markdown"
            )
           
    except Exception as e:
        logger.error(f"Error in checkdomain_handler: {e}")
        await context.bot.edit_message_text(
            chat_id=update.effective_chat.id,
            message_id=processing_msg.message_id,
            text=f"❌ An error occurred while checking domain reputation: {str(e)}"
        )

async def checkhash_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle the /checkhash command"""
    if not context.args:
        await update.message.reply_text(
            "Please provide a file hash to check.\n\n"
            "Usage: `/checkhash <MD5|SHA1|SHA256>`\n\n"
            "Supported hash types: MD5 (32 chars), SHA1 (40 chars), SHA256 (64 chars)",
            parse_mode="Markdown"
        )
        return
   
    file_hash = context.args[0].lower()
   
    # Validate hash format
    hash_type = detect_ioc_type(file_hash) # Merged function, use detect_ioc_type everywhere
    if hash_type not in ["md5", "sha1", "sha256"]:
        await update.message.reply_text(
            "❌ Invalid hash format. Please provide a valid MD5, SHA1, or SHA256 hash.\n\n"
            "Examples:\n"
            "• MD5: `/checkhash 5d41402abc4b2a76b9719d911017c592`\n"
            "• SHA1: `/checkhash aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d`\n"
            "• SHA256: `/checkhash 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08`",
            parse_mode="Markdown"
        )
        return
   
    # Send processing message
    processing_msg = await update.message.reply_text(
        f"🔍 Checking {hash_type.upper()} reputation for `{file_hash}`...",
        parse_mode="Markdown"
    )
   
    try:
        # Check hash reputation
        result = check_hash_reputation(file_hash)
       
        # Store in database
        store_user_logs(update.effective_user.id, f"checkhash {file_hash}", result)
       
        # Format and send results
        if result:
            message = f"*Hash Reputation Results for {file_hash}:*\n\n"
            message += f"*Hash Type:* {hash_type.upper()}\n\n"
           
            for source, data in result.items():
                message += f"*{source}:*\n"
               
                if isinstance(data, dict):
                    if "error" in data:
                        message += f" ❌ {data['error']} (Check API key or connection)\n" # More user-friendly
                    else:
                        # Extract relevant info based on source
                        if source == "VirusTotal" and "data" in data:
                            stats = data["data"].get("attributes", {}).get("last_analysis_stats", {})
                            message += f" ✅ Malicious: {stats.get('malicious', 'N/A')}\n"
                            message += f" ✅ Suspicious: {stats.get('suspicious', 'N/A')}\n"
                            message += f" ✅ Clean: {stats.get('harmless', 'N/A')}\n"
                        elif source == "MalwareBazaar":
                            if "query_status" in data and data["query_status"] == "ok":
                                entry = data.get("data", [{}])[0] # Safely extract first entry
                                message += f" ⚠️ Signature: {entry.get('signature', 'N/A')}\n"
                                message += f" 📁 File Type: {entry.get('file_type', 'N/A')}\n"
                                message += f" 🧪 File Name: {entry.get('file_name', 'N/A')}\n"
                                message += f" 🕒 First Seen: {entry.get('first_seen', 'N/A')}\n"
                                message += f" 📦 MIME Type: {entry.get('file_type_mime', 'N/A')}\n"
                                message += f" 🧬 Imphash: `{entry.get('imphash', 'N/A')}`\n"
                            else:
                                message += f" ✅ No malware information found\n"
                        else:
                            message += f" ℹ️ Data available (use detailed view for more)\n"
                else:
                    message += f" 📝 {str(data)[:100]}...\n"
               
                message += "\n"
           
            await context.bot.edit_message_text(
                chat_id=update.effective_chat.id,
                message_id=processing_msg.message_id,
                text=message,
                parse_mode="Markdown"
            )
        else:
            await context.bot.edit_message_text(
                chat_id=update.effective_chat.id,
                message_id=processing_msg.message_id,
                text=f"❌ Could not retrieve reputation data for `{file_hash}`",
                parse_mode="Markdown"
            )
           
    except Exception as e:
        logger.exception(f"Error in checkhash_handler: {e}")
        await context.bot.edit_message_text(
            chat_id=update.effective_chat.id,
            message_id=processing_msg.message_id,
            text=f"❌ An error occurred while checking hash reputation: {str(e)}"
        )

async def feeds_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle the /feeds command"""
    processing_msg = await update.message.reply_text(
        "📡 Fetching latest threat intelligence feeds...",
        parse_mode="Markdown"
    )
   
    try:
        # Fetch and parse feeds
        feeds = fetch_daily_feeds()
        normalized_data = parse_feed_data(feeds)
       
        if normalized_data:
            # Store in database
            store_user_logs(update.effective_user.id, "feeds", {"count": len(normalized_data)})
           
            # Generate CSV in-memory
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["Indicator", "Type", "Source"]) # Header row
           
            for item in normalized_data:
                writer.writerow([
                    item.get("indicator", "N/A"),
                    item.get("type", "unknown"),
                    item.get("source", "Unknown")
                ])
           
            csv_content = output.getvalue().encode('utf-8')
            output.close()
           
            # Update processing message
            timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
            await context.bot.edit_message_text(
                chat_id=update.effective_chat.id,
                message_id=processing_msg.message_id,
                text=f"✅ Fetched {len(normalized_data)} indicators ({timestamp}). Sending CSV file...",
                parse_mode="Markdown"
            )
           
            # Send the CSV as a document
            await context.bot.send_document(
                chat_id=update.effective_chat.id,
                document=io.BytesIO(csv_content),
                filename=f"threat_feeds_{timestamp.replace(' ', '_')}.csv",
                caption="Latest Threat Intelligence Feeds (full list)"
            )
        else:
            await context.bot.edit_message_text(
                chat_id=update.effective_chat.id,
                message_id=processing_msg.message_id,
                text="❌ No threat intelligence feeds available at the moment.",
                parse_mode="Markdown"
            )
           
    except Exception as e:
        logger.exception(f"Error in feeds_handler: {e}")
        await context.bot.edit_message_text(
            chat_id=update.effective_chat.id,
            message_id=processing_msg.message_id,
            text=f"❌ An error occurred while fetching threat feeds: {str(e)}"
        )

async def help_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle the /help command"""
    help_message = (
        "🛡️ <b>Threat Intelligence Bot Help</b> 🛡️\n\n"
       
        "<b>Available Commands:</b>\n\n"
       
        "• /start - Start the bot and see welcome message\n"
        "• /checkip &lt;IP_address&gt; - Check the reputation of an IP address\n"
        " Example: <code>/checkip 8.8.8.8</code>\n\n"
       
        "• /checkdomain &lt;domain_name&gt; - Check the reputation of a domain\n"
        " Example: <code>/checkdomain example.com</code>\n\n"
       
        "• /checkhash &lt;file_hash&gt; - Check the reputation of a file hash (MD5, SHA1, SHA256)\n"
        " Examples:\n"
        " <code>/checkhash 5d41402abc4b2a76b9719d911017c592</code> (MD5)\n"
        " <code>/checkhash aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d</code> (SHA1)\n"
        " <code>/checkhash 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08</code> (SHA256)\n\n"
       
        "• /correlate &lt;indicator&gt; - Correlate any IOC (IP, domain, hash)\n"
        " Example: <code>/correlate 8.8.8.8</code>\n\n"
       
        "• /feeds - Get the latest threat intelligence feeds from various sources\n\n"
       
        "• /stats - Show your usage statistics\n\n"
       
        "• /help - Show this help message\n\n"
       
        "<b>Data Sources:</b>\n"
        "• AlienVault OTX\n"
        "• VirusTotal\n"
        "• MalwareBazaar\n"
        "• URLhaus\n"
        "• FireHOL\n"
        "• PhishTank\n\n"
       
        "<b>Note:</b> Some features require API keys to be set in the environment variables for full functionality. If errors occur, check logs for details."
    )
   
    await update.message.reply_text(help_message, parse_mode="HTML")

async def correlate_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle the /correlate command for any IOC type."""
    if not context.args:
        await update.message.reply_text(
            "Please provide an indicator (IP, domain, or hash) to correlate.\n\n"
            "Usage: `/correlate <indicator>`",
            parse_mode="Markdown"
        )
        return
    ioc = context.args[0]
    processing_msg = await update.message.reply_text(
        f"🔍 Correlating indicator `{ioc}`...",
        parse_mode="Markdown"
    )
    try:
        # Call your existing ioc_correlation function
        correlation_data = ioc_correlation(ioc)
        store_user_logs(update.effective_user.id, f"correlate {ioc}", correlation_data)
        ioc_type = correlation_data.get("type", "unknown").upper()
        score = correlation_data.get("confidence_score", 0)
        sources_checked = correlation_data.get("sources_checked", 0)
        results = correlation_data.get("results", {})
        # Count successful responses (improved to count non-empty dicts properly)
        successful_sources = len([r for r in results.values() if isinstance(r, dict) and 'error' not in r and bool(r)])
        message = (
            f"🔎 *Correlation Report for {ioc}*\n\n"
            f"Detected Type: *{ioc_type}*\n"
            f"Confidence Score: *{score}%* ({successful_sources}/{sources_checked} sources responded)\n\n"
        )
        for source, data in results.items():
            message += f"*{source}:*\n"
            if isinstance(data, dict):
                if "error" in data:
                    message += f" ❌ {data['error']} (Check API key or connection)\n" # More user-friendly
                else:
                    message += " ✅ Data found\n"
            else:
                message += " ✅ Data found\n"
       
        await context.bot.edit_message_text(
            chat_id=update.effective_chat.id,
            message_id=processing_msg.message_id,
            text=message,
            parse_mode="Markdown"
        )
    except Exception as e:
        logger.exception(f"Error in correlate_handler: {e}")
        await context.bot.edit_message_text(
            chat_id=update.effective_chat.id,
            message_id=processing_msg.message_id,
            text=f"❌ An error occurred during correlation: {str(e)}"
        )

async def stats_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Provides usage statistics for the user from the local DB."""
    user_id = update.effective_user.id
    try:
        from database import DB_FILE  # Import DB_FILE if needed, but since sqlite3.connect uses it, import from config or database
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM user_logs WHERE user_id = ?", (str(user_id),))
        total_cmds_tuple = cursor.fetchone()
        total_cmds = total_cmds_tuple[0] if total_cmds_tuple else 0
        # Create a dictionary to hold command counts
        command_counts = {}
        cursor.execute("SELECT command FROM user_logs WHERE user_id = ?", (str(user_id),))
        all_commands = cursor.fetchall()
        conn.close()
        if all_commands: # Added check to avoid errors if empty
            for cmd_tuple in all_commands:
                if cmd_tuple and cmd_tuple[0]: # Added check for tuple[0] existence
                    base_cmd = cmd_tuple[0].split(' ')[0] # Extract base command
                    command_counts[base_cmd] = command_counts.get(base_cmd, 0) + 1
        stats_msg = f"📊 *Your Usage Statistics*\n\nTotal Commands Used: *{total_cmds}*\n\n*Breakdown:*\n"
        if command_counts:
            for cmd, count in command_counts.items():
                stats_msg += f"• `/{cmd}`: {count} times\n"
        else:
            stats_msg += "No commands used yet."
        await update.message.reply_text(stats_msg, parse_mode="Markdown")
        logger.info(f"Statistics sent to {user_id}.")
    except Exception as e:
        logger.exception(f"Error fetching statistics for {user_id}: {e}")
        await update.message.reply_text("⚠️ Could not retrieve statistics right now.")

# Note: The following functions are marked as unused in the original code. 
# They reference 'bot' which is not defined here (removed in original). 
# If needed, import from telegram import Bot and instantiate with BOT_TOKEN from config.
# For now, commented out.

# async def send_ioc_summary(user_id, ioc_data):
#     """Formats and sends a detailed IOC report to the user."""
#     try:
#         if not ioc_data:
#             await bot.send_message(chat_id=user_id, text="No data available for this IOC.") # Made async
#             return
#         ioc = ioc_data.get("ioc", "Unknown")
#         score = ioc_data.get("confidence_score", "N/A")
#         sources = ", ".join(ioc_data.get("sources", []))
#         threat_type = ioc_data.get("threat_type", "Unknown")
#         text = (
#             f"🔎 *IOC Report*\n\n"
#             f"🆔 IOC: {ioc}\n"
#             f"⚠️ Threat Type: {threat_type}\n"
#             f"📊 Confidence Score: {score}\n"
#             f"📡 Sources: {sources}\n"
#         )
#         await bot.send_message(chat_id=user_id, text=text, parse_mode="Markdown") # Awaited
#         logger.info(f"IOC summary sent to {user_id} for {ioc}.")
#     except Exception as e:
#         logger.exception(f"Error sending IOC summary to {user_id}: {e}")

# async def send_statistics(user_id):
#     """Provides usage statistics for the user from local DB."""
#     try:
#         conn = sqlite3.connect(DB_FILE)
#         cursor = conn.cursor()
#         cursor.execute("SELECT COUNT(*) FROM user_logs WHERE user_id = ?", (str(user_id),))
#         total_cmds = cursor.fetchone()[0]
#         cursor.execute("SELECT command, COUNT(*) FROM user_logs WHERE user_id = ? GROUP BY command", (str(user_id),))
#         command_stats = cursor.fetchall()
#         conn.close()
#         stats_msg = f"📊 *Your Usage Statistics*\n\nTotal Commands Used: {total_cmds}\n\n"
#         for cmd, count in command_stats:
#             stats_msg += f"• {cmd}: {count} times\n"
#         await bot.send_message(chat_id=user_id, text=stats_msg, parse_mode="Markdown") # Awaited
#         logger.info(f"Statistics sent to {user_id}.")
#     except Exception as e:
#         logger.exception(f"Error fetching statistics for {user_id}: {e}")
#         await bot.send_message(chat_id=user_id, text="⚠️ Could not retrieve statistics right now.") # Awaited