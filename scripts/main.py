import base64
import json
import logging
import os
import re
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import List, Dict
import urllib
import pycountry
import requests
from bs4 import BeautifulSoup
import shutil
import telegram_sender

# تنظیمات لاگ
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

TELEGRAM_URLS = [
    "https://t.me/s/prrofile_purple", "https://t.me/s/v2line", "https://t.me/s/v2ray1_ng",
    "https://t.me/s/v2ray_swhil", "https://t.me/s/v2rayng_fast", "https://t.me/s/v2rayng_vpnrog",
    "https://t.me/s/v2raytz", "https://t.me/s/vmessorg", "https://t.me/s/ISVvpn",
    "https://t.me/s/forwardv2ray", "https://t.me/s/PrivateVPNs", "https://t.me/s/VlessConfig",
    "https://t.me/s/V2pedia", "https://t.me/s/v2rayNG_Matsuri", "https://t.me/s/proxystore11",
    "https://t.me/s/DirectVPN", "https://t.me/s/OutlineVpnOfficial", "https://t.me/s/networknim",
    "https://t.me/s/beiten", "https://t.me/s/MsV2ray", "https://t.me/s/foxrayiran",
    "https://t.me/s/DailyV2RY", "https://t.me/s/yaney_01", "https://t.me/s/EliV2ray",
    "https://t.me/s/ServerNett", "https://t.me/s/v2rayng_fa2", "https://t.me/s/v2rayng_org",
    "https://t.me/s/V2rayNGvpni", "https://t.me/s/v2rayNG_VPNN", "https://t.me/s/v2_vmess",
    "https://t.me/s/FreeVlessVpn", "https://t.me/s/vmess_vless_v2rayng", "https://t.me/s/freeland8",
    "https://t.me/s/vmessiran", "https://t.me/s/V2rayNG3", "https://t.me/s/ShadowsocksM",
    "https://t.me/s/ShadowSocks_s", "https://t.me/s/VmessProtocol", "https://t.me/s/Easy_Free_VPN",
    "https://t.me/s/V2Ray_FreedomIran", "https://t.me/s/V2RAY_VMESS_free", "https://t.me/s/v2ray_for_free",
    "https://t.me/s/V2rayN_Free", "https://t.me/s/free4allVPN", "https://t.me/s/configV2rayForFree",
    "https://t.me/s/FreeV2rays", "https://t.me/s/DigiV2ray", "https://t.me/s/v2rayNG_VPN",
    "https://t.me/s/freev2rayssr", "https://t.me/s/v2rayn_server", "https://t.me/s/iranvpnet",
    "https://t.me/s/vmess_iran", "https://t.me/s/configV2rayNG", "https://t.me/s/vpn_proxy_custom",
    "https://t.me/s/vpnmasi", "https://t.me/s/ViPVpn_v2ray", "https://t.me/s/vip_vpn_2022",
    "https://t.me/s/FOX_VPN66", "https://t.me/s/YtTe3la", "https://t.me/s/ultrasurf_12",
    "https://t.me/s/frev2rayng", "https://t.me/s/FreakConfig", "https://t.me/s/Awlix_ir",
    "https://t.me/s/arv2ray", "https://t.me/s/flyv2ray", "https://t.me/s/free_v2rayyy",
    "https://t.me/s/ip_cf", "https://t.me/s/lightning6", "https://t.me/s/mehrosaboran",
    "https://t.me/s/oneclickvpnkeys", "https://t.me/s/outline_vpn", "https://t.me/s/outlinev2rayng",
    "https://t.me/s/outlinevpnofficial", "https://t.me/s/v2rayngvpn", "https://t.me/s/V2raNG_DA",
    "https://t.me/s/V2rayNg_madam", "https://t.me/s/v2boxxv2rayng", "https://t.me/s/configshub2",
    "https://t.me/s/v2ray_configs_pool", "https://t.me/s/hope_net", "https://t.me/s/everydayvpn",
    "https://t.me/s/v2nodes", "https://t.me/s/shadowproxy66", "https://t.me/s/free_nettm"
]

SEND_TO_TELEGRAM = os.getenv('SEND_TO_TELEGRAM', 'false').lower() == 'true'
TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
TELEGRAM_CHAT_ID = os.getenv('TELEGRAM_CHAT_ID')
TELEGRAM_CHANNEL_ID = os.getenv('TELEGRAM_CHANNEL_ID')
SUB_CHECKER_DIR = Path("sub-checker")

def full_unquote(s: str) -> str:
    if '%' not in s:
        return s
    prev_s = ""
    while s != prev_s:
        prev_s = s
        s = urllib.parse.unquote(s)
    return s

def clean_previous_configs(configs: List[str]) -> List[str]:
    cleaned_configs = []
    for config in configs:
        try:
            if '#' in config:
                base_uri, tag = config.split('#', 1)
                decoded_tag = full_unquote(tag)
                # حذف تگ‌های قبلی
                cleaned_tag = re.sub(r'::[A-Z]{2}$', '', decoded_tag).strip()
                # حذف ایموجی‌های پرچم قدیمی اگر وجود داشته باشند (اختیاری)
                # cleaned_tag = re.sub(r'[\U0001F1E6-\U0001F1FF]{2}', '', cleaned_tag).strip()
                
                if cleaned_tag:
                    # اینجا چون تگ‌های قدیمی را تمیز می‌کنیم، بهتر است دوباره انکود شوند تا استاندارد باشند
                    # اما طبق درخواست شما در مرحله نهایی انکود برداشته می‌شود. اینجا چون ورودی است دست نمی‌زنیم
                    final_config = f"{base_uri}#{urllib.parse.quote(cleaned_tag)}"
                else:
                    final_config = base_uri
                cleaned_configs.append(final_config)
            else:
                cleaned_configs.append(config)
        except Exception as e:
            logging.warning(f"Could not clean config, adding original: {config[:50]}... Error: {e}")
            cleaned_configs.append(config)
    return cleaned_configs

def scrape_configs_from_url(url: str) -> List[str]:
    configs = []
    try:
        response = requests.get(url, timeout=20)
        response.raise_for_status()

        channel_name = "@" + url.split("/s/")[1]
        new_tag = ">>DR-Anv"

        soup = BeautifulSoup(response.content, 'html.parser')
        all_text_content = "\n".join(tag.get_text('\n') for tag in soup.find_all(['div', 'code', 'blockquote', 'pre']))

        pattern = r'((?:vmess|vless|ss|hy2|trojan|hysteria2)://[^\s<>"\'`]+)'
        found_configs = re.findall(pattern, all_text_content)

        for config in found_configs:
            if config.startswith("vmess://"):
                try:
                    base_part = config.split('#', 1)[0]
                    encoded_json = base_part.replace("vmess://", "")
                    encoded_json += '=' * (-len(encoded_json) % 4)
                    decoded_bytes = base64.b64decode(encoded_json)

                    try:
                        decoded_json = decoded_bytes.decode("utf-8")
                    except UnicodeDecodeError:
                        decoded_json = decoded_bytes.decode("latin-1")

                    vmess_data = json.loads(decoded_json)
                    vmess_data["ps"] = new_tag

                    updated_json = json.dumps(vmess_data, separators=(',', ':'))
                    updated_b64 = base64.b64encode(updated_json.encode('utf-8')).decode('utf-8').rstrip('=')
                    configs.append("vmess://" + updated_b64)
                except Exception as e:
                    logging.warning(f"Could not parse vmess config, skipping: {config[:50]}... Error: {e}")
            else:
                base_uri = config.split('#', 1)[0]
                configs.append(f"{base_uri}#{urllib.parse.quote(new_tag)}")

        logging.info(f"Found and re-tagged {len(configs)} configs in {url}")
        return configs
    except Exception as e:
        logging.error(f"Could not fetch or parse {url}: {e}")
        return []

def run_sub_checker(input_configs: List[str]) -> List[str]:
    if not SUB_CHECKER_DIR.is_dir():
        logging.error(f"Sub-checker directory not found at '{SUB_CHECKER_DIR}'")
        return []

    normal_txt_path = SUB_CHECKER_DIR / "normal.txt"
    final_txt_path = SUB_CHECKER_DIR / "final.txt"
    cl_py_path = SUB_CHECKER_DIR / "cl.py"

    logging.info(f"Writing {len(input_configs)} configs to '{normal_txt_path}'")
    normal_txt_path.write_text("\n".join(input_configs), encoding="utf-8")

    logging.info("Running sub-checker script (cl.py)...")
    try:
        process = subprocess.run(
            ["python", cl_py_path.name],
            cwd=SUB_CHECKER_DIR,
            capture_output=True,
            text=True,
            timeout=7200
        )
        if process.stderr:
            # خطاها را فقط لاگ می‌کنیم اما ادامه می‌دهیم چون ممکن است warnings باشند
            logging.info("Sub-checker stderr output available (check if critical).")

        if process.returncode != 0:
            logging.error("Sub-checker script failed to execute properly.")
            # برخی اسکریپت‌ها حتی با خطا خروجی می‌دهند، پس ادامه می‌دهیم

        if final_txt_path.exists():
            logging.info("Reading checked configs from 'final.txt'")
            checked_configs = final_txt_path.read_text(encoding="utf-8").splitlines()
            return [line for line in checked_configs if line.strip()]
        else:
            logging.error("'final.txt' was not created by the sub-checker.")
            return []

    except subprocess.TimeoutExpired:
        logging.error("Sub-checker script timed out after 2 hours.")
        return []
    except Exception as e:
        logging.error(f"An error occurred while running sub-checker: {e}")
        return []

def get_country_flag(code: str) -> str:
    """Helper function to get flag emoji from country code using pycountry"""
    try:
        country = pycountry.countries.get(alpha_2=code.upper())
        if country and hasattr(country, 'flag'):
            return country.flag
        return code # اگر پرچم پیدا نشد، خود کد را برگردان
    except:
        return code

def process_and_save_results(checked_configs: List[str]) -> Dict[str, int]:
    if not checked_configs:
        logging.warning("No checked configs to process.")
        return {}

    loc_dir = Path("loc")
    mix_dir = Path("mix")

    logging.info(f"Cleaning up old files in '{loc_dir}' directory...")
    if loc_dir.is_dir():
        try:
            shutil.rmtree(loc_dir)
        except OSError as e:
            logging.error(f"Error removing directory {loc_dir}: {e}")

    loc_dir.mkdir(exist_ok=True)
    mix_dir.mkdir(exist_ok=True)

    configs_by_protocol = {
        "vless": [], "vmess": [], "ss": [], "trojan": [], "hy2": []
    }
    configs_by_location = {}
    
    # لیست نهایی برای ذخیره همه کانفیگ‌های تغییر یافته
    final_modified_configs = []

    for config in checked_configs:
        # 1. استخراج کد کشور (معمولاً چکر به صورت ::US اضافه می‌کند)
        # تغییر: اگر کد کشور پیدا نشد، پیش‌فرض 🏴‍☠️ باشد
        location_code = "🏴‍☠️"
        flag_emoji = "🏴‍☠️"
        
        # دیکد کردن برای پیدا کردن کد کشور
        decoded_config = urllib.parse.unquote(config)
        match = re.search(r'::([A-Za-z]{2})$', decoded_config)
        
        if match:
            location_code = match.group(1).upper()
            flag_emoji = get_country_flag(location_code)
        
        # 2. جایگزینی کد کشور با پرچم در خود کانفیگ
        modified_config = config
        
        try:
            if config.startswith("vmess://"):
                # پردازش VMess
                base_part = config.replace("vmess://", "")
                # اضافه کردن پدینگ اگر لازم باشد
                base_part += '=' * (-len(base_part) % 4)
                
                try:
                    # دیکد کردن base64
                    decoded_bytes = base64.b64decode(base_part)
                    decoded_str = decoded_bytes.decode("utf-8")
                    vmess_data = json.loads(decoded_str)
                    
                    if "ps" in vmess_data:
                        current_ps = vmess_data["ps"]
                        # جایگزینی ::US با پرچم در نام
                        if match:
                             new_ps = re.sub(r'::[A-Za-z]{2}$', f" {flag_emoji}", current_ps)
                             vmess_data["ps"] = new_ps
                        
                        # اینکد کردن مجدد
                        new_json = json.dumps(vmess_data, separators=(',', ':'))
                        new_b64 = base64.b64encode(new_json.encode('utf-8')).decode('utf-8').rstrip('=')
                        modified_config = "vmess://" + new_b64
                except Exception as e:
                    logging.warning(f"Error processing vmess config name: {e}")
                    
            else:
                # پردازش سایر پروتکل‌ها (Vless, Trojan, SS, etc.)
                if '#' in config:
                    base_uri, tag = config.split('#', 1)
                    decoded_tag = urllib.parse.unquote(tag)
                    
                    if match:
                        # جایگزینی ::US با پرچم
                        new_tag = re.sub(r'::[A-Za-z]{2}$', f" {flag_emoji}", decoded_tag)
                        
                        # تغییر: حذف urllib.parse.quote طبق درخواست شما
                        modified_config = f"{base_uri}#{new_tag}"
        except Exception as e:
            logging.warning(f"General error modifying config: {e}")

        # اضافه کردن به لیست کلی تغییر یافته
        final_modified_configs.append(modified_config)

        # 3. دسته‌بندی بر اساس پروتکل
        if modified_config.startswith(("hysteria://", "hysteria2://", "hy2://")):
            configs_by_protocol["hy2"].append(modified_config)
        elif modified_config.startswith("vless://"):
            configs_by_protocol["vless"].append(modified_config)
        elif modified_config.startswith("vmess://"):
            configs_by_protocol["vmess"].append(modified_config)
        elif modified_config.startswith("ss://"):
            configs_by_protocol["ss"].append(modified_config)
        elif modified_config.startswith("trojan://"):
            configs_by_protocol["trojan"].append(modified_config)

        # 4. دسته‌بندی بر اساس لوکیشن (برای فایل‌ها)
        if location_code not in configs_by_location:
            configs_by_location[location_code] = {"configs": [], "flag": flag_emoji}
        configs_by_location[location_code]["configs"].append(modified_config)

    # ذخیره فایل‌های پروتکل
    for proto, configs in configs_by_protocol.items():
        if configs:
            file_path = Path(f"{proto}.html")
            file_path.write_text("\n".join(configs), encoding="utf-8")
            logging.info(f"Saved {len(configs)} configs to '{file_path}'")

    # ذخیره فایل میکس
    Path("mix/sub.html").write_text("\n".join(final_modified_configs), encoding="utf-8")
    logging.info(f"Saved {len(final_modified_configs)} configs to 'mix/sub.html'")

    # ذخیره فایل‌های لوکیشن
    for loc_code, data in configs_by_location.items():
        configs = data["configs"]
        flag = data["flag"]
        
        # نام فایل: US 🇺🇸.txt
        file_name = f"{loc_code} {flag}.txt"
        file_path = Path("loc") / file_name
        file_path.write_text("\n".join(configs), encoding="utf-8")
        logging.info(f"Saved {len(configs)} for location {loc_code} to '{file_path}'")

    protocol_counts = {proto: len(configs) for proto, configs in configs_by_protocol.items()}
    logging.info(f"Final protocol counts: {protocol_counts}")
    return protocol_counts

def main():
    logging.info("--- Starting V2Ray Extractor ---")

    logging.info("Step 1: Scraping new configs from Telegram channels...")
    all_raw_configs = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_url = {executor.submit(scrape_configs_from_url, url): url for url in TELEGRAM_URLS}
        for future in future_to_url:
            all_raw_configs.extend(future.result())

    unique_new_configs = sorted(list(set(all_raw_configs)))
    logging.info(f"Collected {len(unique_new_configs)} unique new configs from Telegram.")

    logging.info("Step 2: Reading previously checked configs from 'mix/sub.html'...")
    previous_configs = []
    previous_mix_file = Path("mix/sub.html")
    if previous_mix_file.is_file():
        try:
            previous_configs = previous_mix_file.read_text(encoding="utf-8").splitlines()
            previous_configs = [line.strip() for line in previous_configs if '://' in line]
            previous_configs = clean_previous_configs(previous_configs)
            logging.info(f"Successfully read {len(previous_configs)} previously checked configs.")
        except Exception as e:
            logging.error(f"Could not read or process '{previous_mix_file}': {e}")
    else:
        logging.info("No previous 'mix/sub.html' file found. Proceeding with new configs only.")

    logging.info("Step 3: Merging new and previous configs...")
    combined_configs = unique_new_configs + previous_configs
    unique_combined_configs = sorted(list(set(combined_configs)))
    logging.info(f"Total unique configs to be tested: {len(unique_combined_configs)}")

    if not unique_combined_configs:
        logging.warning("No configs to check after merging. Exiting.")
        return

    logging.info("Step 4: Running the sub-checker...")
    checked_configs = run_sub_checker(unique_combined_configs)
    logging.info(f"Sub-checker returned {len(checked_configs)} valid configs.")

    logging.info("Step 5: Processing, saving results, and getting counts...")
    # استفاده از تابع جدید که پرچم‌ها را جایگزین می‌کند
    protocol_counts = process_and_save_results(checked_configs)
    
    if SEND_TO_TELEGRAM:
        logging.info("Flag 'sendToTelegram' is true. Proceeding with Telegram notifications.")
        if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID or not TELEGRAM_CHANNEL_ID:
            logging.warning("Telegram notifications are enabled, but bot token or chat/channel ID is missing. Skipping.")
        else:
            if not protocol_counts:
                logging.warning("Protocol counts are empty, skipping summary message.")
            else:
                try:
                    bot = telegram_sender.init_bot(TELEGRAM_BOT_TOKEN)
                    if bot:
                        logging.info(f"Sending summary to main channel: {TELEGRAM_CHANNEL_ID}")
                        telegram_sender.send_summary_message(bot, TELEGRAM_CHANNEL_ID, protocol_counts)

                        logging.info(f"Sending grouped configs to channel: {TELEGRAM_CHANNEL_ID}")
                        # توجه: برای ارسال تلگرام، از کانفیگ‌های اصلاح شده که در فایل‌ها ذخیره شده‌اند استفاده کنید
                        # یا تابع grouping را با checked_configs اصلاح شده فراخوانی کنید.
                        # اینجا چون لیست اصلی checked_configs تغییر نکرده، ممکن است کد قدیمی ارسال شود
                        # مگر اینکه تلگرام سندر فایل‌ها را بخواند.
                        # برای اطمینان بهتر است فایل mix/sub.html را بخوانید:
                        modified_configs = Path("mix/sub.html").read_text(encoding="utf-8").splitlines()
                        grouped_configs = telegram_sender.regroup_configs_by_source(modified_configs)
                        telegram_sender.send_all_grouped_configs(bot, TELEGRAM_CHANNEL_ID, grouped_configs)

                        logging.info("Successfully sent all Telegram notifications.")
                except Exception as e:
                    logging.error(f"An error occurred during Telegram operations: {e}")
    else:
        logging.info("Flag 'sendToTelegram' is false. Skipping Telegram notifications.")

    logging.info("--- V2Ray Extractor finished successfully! ---")

if __name__ == "__main__":
    main()
