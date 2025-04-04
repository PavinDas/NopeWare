import requests
import json
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
from time import sleep

# VirusTotal API settings
VT_SCAN_URL = "https://www.virustotal.com/vtapi/v2/file/scan"
VT_ANALYSIS_URL = "https://www.virustotal.com/api/v3/files/"
with open('api-key.txt', 'r') as f:
    API_KEY = f.read().strip()

# Telegram Bot Token
with open('bot-token.txt', 'r') as f:
    TOKEN = f.read().strip()

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "Welcome to VirusTotal Scanner Bot!\n"
        "Send a file to scan it with VirusTotal.\n\n"
        "Developed by: Your Name\n"
        "GitHub: PavinDas\n"
        "Instagram: pavin__das"
    )

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
        response = requests.post(VT_SCAN_URL, files=file_to_upload, params=params)
    
    sha1 = response.json()['sha1']
    file_url = f"{VT_ANALYSIS_URL}{sha1}"
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
            if total_scans > 10:  # Wait until reasonable number of scans complete
                break
        sleep(15)  # Wait 15 seconds between attempts
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
    result = report["data"]["attributes"]["last_analysis_results"]

    # Build the complete output as a single string
    output = f"Name: {name}\n"
    output += f"Size: {size} KB\n"
    output += f"Description: {descp}\n"
    output += f"SHA-256 Hash: {hash}\n\n"

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
        else:
            verdict = verdict
        output += f"{key}: {verdict}\n"

    if malicious_count != 0:
        output += f"\n\t\t\t\t{malicious_count} antivirus found the given file malicious !!"
    else:
        output += f"\n\t\t\t\t No antivirus found the given file malicious !!"

    # Add VirusTotal link for manual verification
    vt_link = f"https://www.virustotal.com/gui/file/{hash}"
    output += f"\n\nVerify manually: {vt_link}"

    # Send the complete output as a single message
    await message.reply_text(output)

    # Cleanup
    import os
    if os.path.exists(file_path):
        os.remove(file_path)

def main():
    application = Application.builder().token(TOKEN).build()
    
    application.add_handler(CommandHandler("start", start))
    application.add_handler(MessageHandler(filters.Document.ALL, handle_file))
    
    print("Bot is running...")
    application.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == '__main__':
    main()