# yes this was made with ai, problem with it? click away.
import asyncio
import logging
import time
import aiohttp

from typing         import Tuple, List
from dataclasses    import dataclass

from telethon       import TelegramClient, events
from aiohttp        import ClientSession

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

API_ID = 1
API_HASH = ""
BOT_SESSION_NAME = "capi_bot"

if not API_ID or not API_HASH:
    logger.error("API_ID and API_HASH must be set as environment variables.")
    exit(1)

client = TelegramClient(
    BOT_SESSION_NAME,
    int(API_ID),
    API_HASH
)

@dataclass
class ApiConfig:
    label: str
    domain: str
    pk: str
    special_case: bool = False

APIS: List[ApiConfig] = [
    ApiConfig(label="roblox", domain="arkoselabs.roblox.com", pk="A2A14B1D-1AF3-C791-9BBC-EE33CC7A0A6F", special_case=True),
    ApiConfig(label="outlook", domain="client-api.arkoselabs.com", pk="B7D8911C-5CC8-A9A3-35B0-554ACEE604DA"),
    ApiConfig(label="x", domain="client-api.arkoselabs.com", pk="2CB16598-CB82-4CF7-B332-5990DB66F3AB"),
    ApiConfig(label="ea", domain="ea-api.arkoselabs.com", pk="73BEC076-3E53-30F5-B1EB-84F494D43DBA"),
    ApiConfig(label="github", domain="github-api.arkoselabs.com", pk="747B83EC-2CA3-43AD-A7DF-701F286FBABA"),
    ApiConfig(label="meta", domain="meta-api.arkoselabs.com", pk="2BF0FE95-9FB3-45E0-9CB9-3F5B5A8465B1"),
    ApiConfig(label="dev", domain="client-api.arkoselabs.com", pk="11111111-1111-1111-1111-111111111111")
]

CAPI_CACHE = {}
CACHE_DURATION = 45

async def fetch_capi_version_hash(session: ClientSession, api: ApiConfig) -> Tuple[str, str]:
    """
    Fetches the CAPI version and hash from Arkose Labs API.
    
    Args:
        session: The aiohttp client session
        api: The API configuration to use
        
    Returns:
        A tuple of (version, hash) or error information
    """
    try:
        url = f"https://{api.domain}/v2/{api.pk}/api.js"
        async with session.get(url, timeout=10) as response:
            if response.status != 200:
                logger.error(f"Failed to fetch API.js from {url}: Status {response.status}")
                return "Error", f"HTTP {response.status}"
                
            js_content = await response.text()
            
        try: # version 2.x.x
            varm = js_content.split('0,m="')[1].split('"')[0]
            capi_version = varm.split('/')[0]
            enforcement = varm.split('/')[1]
            capi_hash = enforcement.split('.')[1].split('.')[0]
        except IndexError: # expecting version 3.x.x
            try:
                href_parts = js_content.split('file:"')
                if len(href_parts) <= 1:
                    logger.warning(f"Unexpected format in API.js from {url}")
                    return "Unknown", "Unknown"

                capi_string = href_parts[1].split('"')[0]
                capi_parts = capi_string.split("/")
                
                if len(capi_parts) < 2:
                    logger.warning(f"Insufficient parts in CAPI string: {capi_string}")
                    return "Unknown", "Unknown"

                capi_version = capi_parts[0]
                capi_hash = capi_parts[1].split(".")[1] if '.' in capi_parts[1] else "Unknown"
            except Exception as parse_error:
                logger.warning(f"Failed to parse version/hash: {parse_error}")
                return "Unknown", "Parse failed"

        return capi_version, capi_hash

    except asyncio.TimeoutError:
        logger.error("Request timed out when fetching CAPI data")
        return "Error", "Request timed out"
    except Exception as e:
        logger.exception(f"Error fetching CAPI data: {str(e)}")
        return "Error", str(e)

async def get_capi_data(api_label: str, pk: str) -> Tuple[str, str, bool]:
    """
    Gets CAPI version and hash, using cache when possible.
    
    Args:
        api_label: The label identifying the API
        pk: The public key for the API
        
    Returns:
        Tuple of (version, hash, cache_used)
    """
    cache_key = f"{api_label.lower()}_{pk}"
    current_time = time.time()
    cache_used = False

    if cache_key in CAPI_CACHE:
        cached_entry = CAPI_CACHE[cache_key]
        if current_time - cached_entry['timestamp'] <= CACHE_DURATION:
            logger.info(f"Using cached data for {api_label}")
            return cached_entry['capi_version'], cached_entry['capi_hash'], True
        else:
            logger.info(f"Cache expired for {api_label}, fetching fresh data")
            del CAPI_CACHE[cache_key]

    api = next((api for api in APIS if api.label.lower() == api_label.lower() and api.pk == pk), None)
    if not api:
        logger.warning(f"No API configuration found for {api_label} with PK: {pk}")
        return "Not Found", "Invalid API label or key", False

    async with aiohttp.ClientSession() as session:
        capi_version, capi_hash = await fetch_capi_version_hash(session, api)
        
        if capi_version not in ["Error", "Unknown"]:
            CAPI_CACHE[cache_key] = {
                'capi_version': capi_version,
                'capi_hash': capi_hash,
                'timestamp': current_time
            }
        
        return capi_version, capi_hash, cache_used

async def get_capi_by_site(api: ApiConfig) -> Tuple[str, str, bool]:
    """
    Helper function to fetch CAPI data using a predefined API config.
    
    Args:
        api: The API configuration to use
        
    Returns:
        Tuple of (version, hash, cache_used)
    """
    cache_key = f"{api.label.lower()}_{api.pk}"
    current_time = time.time()

    if cache_key in CAPI_CACHE:
        cached_entry = CAPI_CACHE[cache_key]
        if current_time - cached_entry['timestamp'] <= CACHE_DURATION:
            return cached_entry['capi_version'], cached_entry['capi_hash'], True
        else:
            del CAPI_CACHE[cache_key]

    async with aiohttp.ClientSession() as session:
        capi_version, capi_hash = await fetch_capi_version_hash(session, api)
        
        if capi_version not in ["Error", "Unknown"]:
            CAPI_CACHE[cache_key] = {
                'capi_version': capi_version,
                'capi_hash': capi_hash,
                'timestamp': current_time
            }
        
        return capi_version, capi_hash, False

@client.on(events.NewMessage(pattern=r"(?i)^/capi(?:\s+(\w+))?(?:\s+([\w\-]+))?$"))
async def handle_capi_command(event: events.NewMessage.Event):
    """
    Handles /capi command to fetch CAPI version and hash.
    Usage: /capi [api_label] [pk]
    """
    api_label = event.pattern_match.group(1)
    pk = event.pattern_match.group(2)

    if not api_label or not pk:
        await event.respond(
            "📝 **Usage:** `/capi [api_label] [pk]`\n"
            "**Example:** `/capi roblox A2A14B1D-1AF3-C791-9BBC-EE33CC7A0A6F`",
            parse_mode='markdown'
        )
        return

    capi_version, capi_hash, cache_used = await get_capi_data(api_label, pk)

    if capi_version == "Error":
        await event.respond(f"⚠️ **Error:** {capi_hash}", parse_mode='markdown')
    elif capi_version == "Unknown":
        await event.respond(f"⚠️ **Unable to determine CAPI version or hash.**", parse_mode='markdown')
    elif capi_version == "Not Found":
        await event.respond(f"❌ **{capi_hash}**", parse_mode='markdown')
    else:
        cache_indicator = " | **CACHE: TRUE**" if cache_used else ""
        response = (
            f"**CAPI Information**\n"
            f"• **API:** `{api_label}`\n"
            f"• **PK:** `{pk}`\n"
            f"• **Version:** `v{capi_version}`\n"
            f"• **Hash:** `{capi_hash}`{cache_indicator}"
        )
        await event.respond(response, parse_mode='markdown')

@client.on(events.NewMessage(pattern=r"(?i)^/capi-site(?:\s+(\w+))?$"))
async def handle_capi_site_command(event: events.NewMessage.Event):
    """
    Handles /capi-site command to fetch CAPI details by site label.
    Usage: /capi-site [api_label]
    """
    api_label = event.pattern_match.group(1)

    if not api_label:
        await event.respond(
            "📝 **Usage:** `/capi-site [api_label]`\n"
            "**Example:** `/capi-site roblox`", 
            parse_mode='markdown'
        )
        return

    api = next((api for api in APIS if api.label.lower() == api_label.lower()), None)
    if not api:
        await event.respond(
            f"❌ **No API found with label '{api_label}'**\n"
            f"Use `/support-capi` to see available APIs.", 
            parse_mode='markdown'
        )
        return

    capi_version, capi_hash, cache_used = await get_capi_by_site(api)

    if capi_version == "Error":
        await event.respond(f"⚠️ **{api.label.capitalize()}:** Error: {capi_hash}", parse_mode='markdown')
    elif capi_version == "Unknown":
        await event.respond(f"⚠️ **{api.label.capitalize()}:** Unable to determine CAPI version or hash.", parse_mode='markdown')
    else:
        cache_indicator = " | **CACHE: TRUE**" if cache_used else ""
        response = (
            f"**{api.label.capitalize()} CAPI Information**\n"
            f"• **API:** `{api.domain}`\n"
            f"• **PK:** `{api.pk}`\n"
            f"• **Version:** `v{capi_version}`\n"
            f"• **Hash:** `{capi_hash}`{cache_indicator}"
        )
        await event.respond(response, parse_mode='markdown')

@client.on(events.NewMessage(pattern=r"(?i)^/support-capi$"))
async def handle_support_command(event: events.NewMessage.Event):
    """
    Lists all supported APIs.
    """
    if not APIS:
        await event.respond("No APIs are currently supported.", parse_mode='markdown')
        return

    sites_list = "\n".join(
        [
            f"• **{api.label.capitalize()}**: [API Link](https://{api.domain}/v2/{api.pk}/api.js)"
            for api in APIS
        ]
    )
    
    response = (
        f"**📋 Supported APIs:**\n\n{sites_list}\n\n"
        f"Use `/capi [api_label] [pk]` to get CAPI details."
    )
    await event.respond(response, parse_mode='markdown')

@client.on(events.NewMessage(pattern=r"(?i)^/capi-help$"))
async def handle_help_command(event: events.NewMessage.Event):
    """
    Provides help information about available commands.
    """
    help_text = (
        "**🤖 CAPI Bot Help**\n\n"
        "**Available Commands:**\n\n"
        "• `/capi [api_label] [pk]` - Fetch CAPI version and hash for a specific API.\n"
        "  - *Example:* `/capi roblox A2A14B1D-1AF3-C791-9BBC-EE33CC7A0A6F`\n\n"
        "• `/capi-site [api_label]` - Get CAPI details by site label.\n"
        "  - *Example:* `/capi-site roblox`\n\n"
        "• `/support-capi` - List all supported APIs.\n\n"
        "• `/capi-help` - Show this help message."
    )
    await event.respond(help_text, parse_mode='markdown')

@client.on(events.NewMessage(pattern=r"(?i)^/list-apis$"))
async def handle_list_apis_command(event: events.NewMessage.Event):
    """
    Lists all available API labels in a compact format.
    """
    if not APIS:
        await event.respond("No APIs are currently supported.", parse_mode='markdown')
        return

    api_labels = ", ".join([f"`{api.label}`" for api in APIS])
    response = (
        f"**Available API Labels:** {api_labels}\n\n"
        f"Use `/capi-site [label]` to get details for a specific API."
    )
    await event.respond(response, parse_mode='markdown')

async def start_bot():
    """
    Starts the bot and keeps it running until disconnected.
    """
    await client.start()
    logger.info("✅ CAPI Bot is now online and ready!")
    await client.run_until_disconnected()

def main():
    """
    Main entry point that handles startup and graceful shutdown.
    """
    try:
        logger.info("Starting CAPI Bot...")
        asyncio.run(start_bot())
    except (KeyboardInterrupt, SystemExit):
        logger.info("Bot shutdown requested, closing gracefully.")
    except Exception as e:
        logger.critical(f"Unexpected error: {str(e)}")
        raise
    finally:
        logger.info("Bot has been shut down.")

if __name__ == "__main__":
    main()
