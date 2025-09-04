import os
import logging
from dotenv import load_dotenv

# Load the .env variables
load_dotenv()

# Logging setup
logging.basicConfig(format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO)
logger = logging.getLogger(__name__)

# Telegram Bot Token
BOT_TOKEN = os.getenv("Telegram_BOT_TOKEN")

# Database file
DB_FILE = os.path.abspath("ioc_bot.db")