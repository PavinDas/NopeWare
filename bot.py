import requests
import json
import re
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
from time import sleep

# VirusTotal API settings
VT_FILE_SCAN_URL = "https://www.virustotal.com/vtapi/v2/file/scan"
VT_FILE_ANALYSIS_URL = "https://www.virustotal.com/api/v3/files/"
VT_URL_SCAN_URL = "https://www.virustotal.com/vtapi/v2/url/scan"
VT_URL_ANALYSIS_URL = "https://www.virustotal.com/api/v3/urls/"
with open('api-key.txt', 'r') as f:
    API_KEY = f.read().strip()

# Telegram Bot Token
with open('bot-token.txt', 'r') as f:
    TOKEN = f.read().strip()

# Helper function to detect if text is a hash (MD5, SHA1, SHA256)
def is_hash(text: str) -> bool:
    # MD5: 32 chars, SHA1: 40 chars, SHA256: 64 chars (hexadecimal)
    hash_patterns = [
        r'^[0-9a-fA-F]{32}$',  # MD5
        r'^[0-9a-fA-F]{40}$',  # SHA1
        r'^[0-9a-fA-F]{64}$'   # SHA256
    ]
    return any(re.match(pattern, text) for pattern in hash_patterns)

# Helper function to detect if text is a URL
def is_url(text: str) -> bool:
    url_pattern = r'^(https?://)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(/.*)?$'
    return bool(re.match(url_pattern, text))

# Function to format and send analysis results
async def send_analysis_results(message, report, name, descp=None, size=None, hash_value=None):
    output = f"Name: {name}\n"
    if size:
        output += f"Size: {size} KB\n"
    if descp:
        output += f"Description: {descp}\n"
    if hash_value:
        output += f"Hash: {hash_value}\n"

    # Extract results
    if "data" in report and "attributes" in report["data"]:
        result = report["data"]["attributes"].get("last_analysis_results", {})
        malicious_count = 0
        for key, values in result.items():
            verdict = values['category']
            if verdict == 'undetected':
                verdict = 'undetected'
            elif verdict == 'type-unsupported':
                verdict = 'type-unsupported'
            elif verdict == 'malicious':
                malicious_count += 1
                verdict = 'malicious'
                output += f"\n{key}: {verdict}\n"
            else:
                verdict = verdict

        if malicious_count != 0:
            output += f"\n\t\t\t\t According to {malicious_count} antiviruses, this file is malicious !!"
        else:
            output += f"\n\t\t\t\t This is all clear – no malicious behavior to worry about !!"

        # Add VirusTotal link for manual verification
        hash_key = hash_value if hash_value else report["data"]["attributes"].get("sha256", "")
        if hash_key:
            vt_link = f"https://www.virustotal.com/gui/file/{hash_key}"
            output += f"\n\nVerify manually: {vt_link}"
    else:
        output += "\nNo analysis results available."

    await message.reply_text(output)

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "Welcome to NopeWare Scanner Bot!\n"
        "I can scan:\n- Files: Send any file\n- Hashes: Send MD5, SHA1, or SHA256 hash\n- URLs: Send a URL\n\n"
        "Developed by: @pavin_das\n"
        "GitHub: PavinDas\n"
        "Instagram: pavin__das"
    )

async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = update.message
    text = message.text.strip()

    # Check if the text is a hash
    if is_hash(text):
        await message.reply_text("Detected a hash. Analyzing...")
        headers = {"accept": "application/json", "x-apikey": API_KEY}
        file_url = f"{VT_FILE_ANALYSIS_URL}{text}"

        # Retry mechanism
        max_attempts = 5
        attempt = 0
        while attempt < max_attempts:
            response = requests.get(file_url, headers=headers)
            report = json.loads(response.text)
            if "data" in report and "attributes" in report["data"]:
                stats = report["data"]["attributes"].get("last_analysis_stats", {})
                total_scans = sum(stats.values())
                if total_scans > 10:
                    break
            sleep(15)
            attempt += 1
            await message.reply_text(f"Still analyzing... (Attempt {attempt + 1}/{max_attempts})")

        if attempt >= max_attempts:
            await message.reply_text("Analysis timed out. Please try again later.")
            return

        await send_analysis_results(message, report, name=f"Hash: {text}", hash_value=text)

    # Check if the text is a URL
    elif is_url(text):
        await message.reply_text("Detected a URL. Analyzing...")
        params = {"apikey": API_KEY, "url": text}
        response = requests.post(VT_URL_SCAN_URL, data=params)
        scan_response = response.json()
        
        if "scan_id" not in scan_response:
            await message.reply_text("Failed to scan URL. Please try again.")
            return

        # Extract URL ID for analysis (base64 encoded URL)
        import base64
        url_id = base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")
        analysis_url = f"{VT_URL_ANALYSIS_URL}{url_id}"
        headers = {"accept": "application/json", "x-apikey": API_KEY}

        # Retry mechanism
        max_attempts = 5
        attempt = 0
        while attempt < max_attempts:
            response = requests.get(analysis_url, headers=headers)
            report = json.loads(response.text)
            if "data" in report and "attributes" in report["data"]:
                stats = report["data"]["attributes"].get("last_analysis_stats", {})
                total_scans = sum(stats.values())
                if total_scans > 10:
                    break
            sleep(15)
            attempt += 1
            await message.reply_text(f"Still analyzing... (Attempt {attempt + 1}/{max_attempts})")

        if attempt >= max_attempts:
            await message.reply_text("Analysis timed out. Please try again later.")
            return

        await send_analysis_results(message, report, name=f"URL: {text}")

    else:
        await message.reply_text("Please send a valid hash (MD5, SHA1, SHA256) or URL.")

async def handle_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = update.message
    file = message.document
    
    if not file:
        await message.reply_text("Please send a file to scan.")
        return

    # Get file and download with correct filename
    original_filename = file.file_name if file.file_name else f"unknown_file_{file.file_id}"
    file_path = original_filename
    file_obj = await context.bot.get_file(file.file_id)
    await file_obj.download_to_drive(file_path)

    # Send initial message to indicate processing
    await message.reply_text("Analyzing...")

    # VirusTotal scanning
    params = {"apikey": API_KEY}
    with open(file_path, "rb") as f:
        file_to_upload = {"file": f}
        response = requests.post(VT_FILE_SCAN_URL, files=file_to_upload, params=params)
    
    sha1 = response.json()['sha1']
    file_url = f"{VT_FILE_ANALYSIS_URL}{sha1}"
    headers = {"accept": "application/json", "x-apikey": API_KEY}

    # Retry mechanism to ensure analysis completes
    max_attempts = 5
    attempt = 0
    while attempt < max_attempts:
        response = requests.get(file_url, headers=headers)
        report = json.loads(response.text)
        
        if "data" in report and "attributes" in report["data"]:
            stats = report["data"]["attributes"].get("last_analysis_stats", {})
            total_scans = sum(stats.values())
            if total_scans > 10:
                break
        sleep(15)
        attempt += 1
        await message.reply_text(f"Still analyzing... (Attempt {attempt + 1}/{max_attempts})")

    if attempt >= max_attempts:
        await message.reply_text("Analysis timed out. Please try again later.")
        return

    # Extract report details
    name = report["data"]["attributes"].get("meaningful_name", original_filename)
    hash = report["data"]["attributes"]["sha256"]
    descp = report["data"]["attributes"]["type_description"]
    size = report["data"]["attributes"]["size"] * 10**-3

    await send_analysis_results(message, report, name=name, descp=descp, size=size, hash_value=hash)

    # Cleanup
    import os
    if os.path.exists(file_path):
        os.remove(file_path)

def main():
    application = Application.builder().token(TOKEN).build()
    
    application.add_handler(CommandHandler("start", start))
    application.add_handler(MessageHandler(filters.Document.ALL, handle_file))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
    
    print("Bot is running...")
    application.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == '__main__':
    main()