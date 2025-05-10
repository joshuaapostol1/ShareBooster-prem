from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.live import Live
from rich.table import Table
from rich.layout import Layout
from rich.align import Align
from rich.padding import Padding
from rich.spinner import Spinner
from rich.prompt import Prompt

import urllib.parse
import requests
import json
import sys
import os
import re
import time
from datetime import datetime
import hashlib
import itertools

auth_url = "https://b-api.facebook.com/method/auth.login"
business_api = "https://business.facebook.com/content_management"
graph_api = "https://graph.facebook.com/me/feed"

session_cache_file = ".session.json"
request_timeout = 15
share_interval_seconds = 0.0001 
max_log_entries = 500


class ShareBooster:
    
    xor = "how"
    error_border = "bold #FF4136"
    error_text = "bold #FF4136"
    success_border = "bold #2ECC40"
    success_text = "bold #2ECC40"
    info_border = "bold #0074D9"
    info_text = "bold #7FDBFF"
    warning_border = "bold #FF851B"
    warning_text = "bold #FF851B"
    
    allen_kalbo = "af804fc5d79cf1f861f7964b5437bb327827f452ce37f9d398e171faeb7b99c0"
    
    credit_original = "italic #B0B0B0"
    credit_modifier = "italic #A0A0FF"
    prompt_bracket = "bold #00FF00"
    prompt_symbol = "bold #00FFFF"
    table_header = "bold #F0F8FF"
    column_attempt = "cyan"
    column_time = "magenta"
    column_details = "dim #D3D3D3"

    premium_main_color = "gold1"
    premium_title_color = "#FFBF00"
    
    premium_badge = f"bold {premium_main_color}"
    premium_panel_border = f"bold {premium_main_color}"
    premium_panel_title = f"bold {premium_title_color}"
    script_name_style = "bold chartreuse1"

    tite = "3a1a1e483d12070818"
    
    pussy = "220004001a16482e07071c030703"


    def _xor_cipher_bytes(self, text_bytes, key_bytes):
        return bytes(b ^ k for b, k in zip(text_bytes, itertools.cycle(key_bytes)))

    def _get_decrypted_original_author(self):
        key_bytes = self.xor.encode('utf-8')
        encrypted_bytes = bytes.fromhex(self.tite)
        decrypted_bytes = self._xor_cipher_bytes(encrypted_bytes, key_bytes)
        return decrypted_bytes.decode('utf-8')

    def _get_decrypted_modifier_name(self):
        key_bytes = self.xor.encode('utf-8')
        encrypted_bytes = bytes.fromhex(self.pussy)
        decrypted_bytes = self._xor_cipher_bytes(encrypted_bytes, key_bytes)
        return decrypted_bytes.decode('utf-8')

    def __init__(self):
        self._verify_credits()
        self.stderr = Console(stderr=True, theme=self._create_theme())
        self.stdout = Console(theme=self._create_theme())
        self.session = requests.Session()
        self.post_url = ""
        self.post_id = None
        self.email = None
        self.password = None
        self.cookies_string = ""
        self.access_token = None
        self.cached_data = self._load_cached_data()
        self.cookies_string = self.cached_data.get("cookies_string", "")
        self.share_attempt_count = 0
        self.success_share_count = 0
        self.error_share_count = 0

    def _verify_credits(self):
        try:
            decrypted_original_author = self._get_decrypted_original_author()
            decrypted_modifier_name = self._get_decrypted_modifier_name()
        except Exception:
            print("CRITICAL ERROR: Credit decryption failed. Script may be corrupted.")
            print("Exiting due to integrity issue.")
            sys.exit(102)

        current_combined = f"{decrypted_original_author}|{decrypted_modifier_name}"
        current_allen_kalbo = hashlib.sha256(current_combined.encode()).hexdigest()

        if current_allen_kalbo != self.allen_kalbo:
            print("CRITICAL ERROR: Script integrity compromised. Credits have been modified or key is incorrect.")
            print(f"This script is intended to credit:")
            print(f"  Original Author: (Protected)")
            print(f"  Modified by: (Protected)")
            print("Exiting due to unauthorized modification.")
            sys.exit(101)

    def _create_theme(self):
        from rich.theme import Theme
        return Theme({
            "error": self.error_text,
            "success": self.success_text,
            "info": self.info_text,
            "warning": self.warning_text,
            "prompt_bracket_text": self.prompt_bracket,
            "prompt_symbol": self.prompt_symbol,
        })

    def _load_cached_data(self):
        try:
            with open(session_cache_file, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return {}
        except Exception as e:
            console_to_use = getattr(self, 'stderr', Console(stderr=True))
            console_to_use.print(f"[bold red]ERROR[/]: Failed to load cached data: {e}")
            sys.exit(1)


    def _save_cached_data(self):
        try:
            with open(session_cache_file, "w") as f:
                json.dump(self.cached_data, f, indent=2)
        except Exception as e:
            self._display_message(f"Failed to save cached data: {e}",
                                  style_type="error")

    def _display_message(self,
                         message,
                         title="Info",
                         style_type="info",
                         panel=True):
        console_method = self.stderr.print if style_type == "error" else self.stdout.print
        border_style = self.info_border
        
        if style_type == "error":
            border_style = self.error_border
            title_style = self.error_text
        elif style_type == "success":
            border_style = self.success_border
            title_style = self.success_text
        elif style_type == "warning":
            border_style = self.warning_border
            title_style = self.warning_text
        else: 
            border_style = self.info_border
            title_style = self.info_text


        if panel:
            console_method(
                Panel(Text.from_markup(f"[{style_type}]{message}[/{style_type}]"), 
                      title=f"[{title_style}]{title}[/]", 
                      border_style=border_style,
                      expand=False))
        else:
            console_method( 
                Text.from_markup(f"[{title_style}]{title}:[/] [{style_type}]{message}[/{style_type}]")
            )


    def _clear_screen(self):
        os.system("cls" if os.name == "nt" else "clear")

    def _get_business_page_headers(self):
        return {
            'authority':
            'business.facebook.com',
            'accept':
            'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
            'accept-language':
            'en-US,en;q=0.9',
            'cache-control':
            'max-age=0',
            'cookie':
            self.cookies_string,
            'referer':
            'https://www.facebook.com/',
            'sec-ch-ua':
            '".Not/A)Brand";v="99", "Google Chrome";v="103", "Chromium";v="103"',
            'sec-ch-ua-mobile':
            '?0',
            'sec-ch-ua-platform':
            '"Linux"',
            'sec-fetch-dest':
            'document',
            'sec-fetch-mode':
            'navigate',
            'sec-fetch-site':
            'same-origin',
            'sec-fetch-user':
            '?1',
            'upgrade-insecure-requests':
            '1',
            'user-agent':
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36'
        }

    def _prompt_ask(self,
                    bracket_content: str,
                    prompt_indicator: str = "~",
                    password: bool = False) -> str:
        prompt_text = Text.assemble(
            ("┌─[", "dim white"), (bracket_content, "prompt_bracket_text"),
            ("]─────[", "dim white"), ("#", "prompt_symbol"),
            ("]\n└─[", "dim white"), (prompt_indicator, "prompt_bracket_text"),
            ("]────► ", "prompt_symbol"))
        
        if password:
            return Prompt.ask(prompt_text, password=True, console=self.stdout)
        else:
            self.stdout.print(prompt_text, end="")
            user_input = self.stdout.input() 
            return user_input.strip()


    def _prompt_credentials(self):
        self.stdout.print(
            Panel(Text("Facebook login required to continue.", style=self.info_text), 
                  title=f"[{self.info_text}]Authentication[/]",
                  border_style=self.info_border,
                  expand=False
            ))
        self.email = self._prompt_ask("Email/Username", prompt_indicator="~")
        self.password = self._prompt_ask("Password",
                                         prompt_indicator="~",
                                         password=False)

    def fetch_cookies(self):
        with self.stdout.status(Text.from_markup(
                f"[{self.info_text}]Authenticating and fetching cookies...[/]"),
                                spinner="dots12"):
            params = {
                'adid': 'e3a395f9-84b6-44f6-a0ce-fe83e934fd4d',
                'email': self.email,
                'password': self.password,
                'format': 'json',
                'device_id': '67f431b8-640b-4f73-a077-acc5d3125b21',
                'cpl': 'true',
                'family_device_id': '67f431b8-640b-4f73-a077-acc5d3125b21',
                'locale': 'en_US',
                'client_country_code': 'US',
                'credentials_type': 'device_based_login_password',
                'generate_session_cookies': '1',
                'generate_analytics_claim': '1',
                'generate_machine_id': '1',
                'currently_logged_in_userid': '0',
                'irisSeqID': '1',
                'try_num': '1',
                'enroll_misauth': 'false',
                'meta_inf_fbmeta': 'NO_FILE',
                'source': 'login',
                'machine_id': 'KBz5fEj0GAvVAhtufg3nMDYG',
                'fb_api_req_friendly_name': 'authenticate',
                'fb_api_caller_class':
                'com.facebook.account.login.protocol.Fb4aAuthHandler',
                'api_key': '882a8490361da98702bf97a021ddc14d',
                'access_token': '350685531728|62f8ce9f74b12f84c123cc23437a4a32'
            }
            full_url = auth_url + "?" + urllib.parse.urlencode(params)
            try:
                response = self.session.get(full_url, timeout=request_timeout)
                response.raise_for_status()
                data = response.json()
            except requests.exceptions.Timeout:
                self._display_message("Login request timed out.",
                                      title="Login Error",
                                      style_type="error")
                return False
            except requests.exceptions.RequestException as e:
                self._display_message(f"Network error during login: {e}",
                                      title="Login Error",
                                      style_type="error")
                return False
            except json.JSONDecodeError:
                self._display_message(
                    f"Invalid response from login server: {response.text[:200]}",
                    title="Login Error",
                    style_type="error")
                return False
        if 'session_cookies' in data:
            self.cookies_string = "; ".join(
                f"{cookie['name']}={cookie['value']}"
                for cookie in data['session_cookies'])
            self.cached_data['cookies_string'] = self.cookies_string
            self._save_cached_data()
            self._display_message("Cookies obtained successfully!",
                                  title="Login Success",
                                  style_type="success")
            return True
        else:
            error_msg = data.get(
                'error_msg',
                data.get('error', {}).get('message', str(data)))
            self._display_message(
                f"Failed to get cookies. API Response: {error_msg}",
                title="Login Failed",
                style_type="error")
            return False

    def fetch_access_token(self):
        with self.stdout.status(
                Text.from_markup(f"[{self.info_text}]Fetching access token...[/]"),
                spinner="moon"):
            headers = self._get_business_page_headers()
            try:
                response = self.session.get(business_api,
                                            headers=headers,
                                            timeout=request_timeout)
                response.raise_for_status()
                content = response.text
                token_match = re.search(r'["\'](EAAG\w+)["\']', content)
                if token_match:
                    self.access_token = token_match.group(1)
                    self._display_message(
                        "Access token obtained successfully.",
                        title="Token Acquired",
                        style_type="success")
                    return True
                else:
                    self._display_message(
                        "Could not extract access token. Page structure might have changed or cookies are invalid.",
                        title="Token Error",
                        style_type="error")
                    if "login" in response.url.lower(
                    ) or "checkpoint" in response.url.lower():
                        self._display_message(
                            "Redirected to login/checkpoint. Cookies might be expired.",
                            title="Token Error Hint", 
                            style_type="warning")
                        self.cookies_string = "" 
                        self.cached_data.pop('cookies_string', None)
                        self._save_cached_data()
                    return False
            except requests.exceptions.Timeout:
                self._display_message("Request for access token timed out.",
                                      title="Token Error",
                                      style_type="error")
                return False
            except requests.exceptions.RequestException as e:
                self._display_message(
                    f"Network error while fetching access token: {e}",
                    title="Token Error",
                    style_type="error")
                return False
            except AttributeError: 
                self._display_message(
                    "Failed to parse access token structure (AttributeError).",
                    title="Token Error",
                    style_type="error")
                return False


    def _generate_live_layout(self, log_table):
        layout = Layout(name="root")
        layout.split_column(Layout(name="header", size=3), Layout(name="log_display_area"))
        
        summary_text = Text.assemble(
            ("Shares: ", f"bold {self.column_attempt}"), 
            (f"{self.share_attempt_count}", self.column_attempt),
            (" Attempted / ", f"bold {self.success_text}"),
            (f"{self.success_share_count}", self.success_text),
            (" Succeeded / ", f"bold {self.error_text}"),
            (f"{self.error_share_count}", self.error_text),
            (" Failed", f"bold {self.error_text}"), 
            (" | Plan: ", f"bold {self.premium_title_color}"), 
            ("PREMIUM", f"{self.premium_badge}") 
        )
        header_panel = Panel(
            Align.center(summary_text),
            title=f"[{self.premium_panel_title}]📊 Live Share Statistics[/]",
            border_style=self.premium_panel_border,
            padding=(0, 1),
            title_align="center"
        )
        layout["header"].update(header_panel)
        layout["log_display_area"].update(log_table)
        return layout

    def perform_share(self):
        share_url = f"{graph_api}?link=https://m.facebook.com/{self.post_id}&published=0&access_token={self.access_token}"
        share_headers = {
            'accept': '*/*',
            'accept-encoding': 'gzip, deflate',
            'connection': 'keep-alive',
            'cookie': self.cookies_string,
            'host': 'graph.facebook.com',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36 Edg/90.0.818.51'
        }
        log_table = Table(
            title=f"[{self.info_text}]Sharing Log for Post ID: [bold cyan]{self.post_id}[/bold cyan][/]",
            show_lines=False,
            expand=True,
            border_style=self.info_border, 
            header_style=self.table_header,
            title_align="center"
        )
        log_table.add_column("Attempt",
                             justify="right",
                             style=self.column_attempt,
                             no_wrap=True,
                             min_width=7)
        log_table.add_column("Time", style=self.column_time, min_width=10)
        log_table.add_column("Status", min_width=15)
        log_table.add_column("Details",
                             style=self.column_details,
                             overflow="fold",
                             min_width=40)

        self.stdout.print(
            Padding(
                Panel(Text.from_markup(
                    f"[{self.info_text}]Starting shares for Post ID: [bold cyan]{self.post_id}[/bold cyan]. Press [bold red]Ctrl+C[/bold red] to stop.[/]"
                ),
                      title=f"[{self.info_text}]Action[/]",
                      border_style=self.info_border,
                      expand=False,
                      title_align="center"), 
                      (1, 0, 1, 0) 
            )
        )

        current_live_instance = None
        loop_exited_unexpectedly = True 

        try:
            with Live(self._generate_live_layout(log_table),
                      console=self.stdout,
                      refresh_per_second=4, 
                      screen=False, 
                      vertical_overflow="visible") as live:
                current_live_instance = live
                try:
                    while True:
                        self.share_attempt_count += 1
                        timestamp = datetime.now().strftime("%H:%M:%S")
                        status_icon, status_text, details_text, status_style_tag = "", "", "", ""
                        
                        current_status_style_for_text = self.info_text 

                        raw_response_text_debug = ""

                        try:
                            response = self.session.post(
                                share_url,
                                headers=share_headers,
                                timeout=request_timeout)
                            raw_response_text_debug = response.text
                            data = response.json()
                            response.raise_for_status() 

                            if 'id' in data:
                                self.success_share_count += 1
                                status_icon, status_text, details_text = "✅", "Success", f"FB ID: {data['id']}"
                                current_status_style_for_text = self.success_text
                            else: 
                                self.error_share_count += 1
                                error_detail = data.get('error', {}).get('message', str(data))
                                status_icon, status_text, details_text = "❌", "Failed (API)", error_detail
                                current_status_style_for_text = self.error_text

                        except requests.exceptions.HTTPError as e:
                            self.error_share_count += 1
                            status_icon = "❌"
                            status_text = f"HTTP Error {e.response.status_code}"
                            current_status_style_for_text = self.error_text
                            try:
                                fb_error_data = e.response.json()
                                details_text = fb_error_data.get('error', {}).get('message', e.response.text[:100])
                            except json.JSONDecodeError:
                                details_text = e.response.text[:100] 
                        
                        except requests.exceptions.Timeout:
                            self.error_share_count += 1
                            status_icon, status_text, details_text = "⏳", "Timeout", f"Request timed out after {request_timeout}s."
                            current_status_style_for_text = self.warning_text
                        except requests.exceptions.RequestException as e: 
                            self.error_share_count += 1
                            status_icon, status_text, details_text = "❌", "Network Error", str(e)
                            current_status_style_for_text = self.error_text
                        except json.JSONDecodeError:
                            self.error_share_count += 1
                            snippet = raw_response_text_debug[:100] if raw_response_text_debug else "Response was empty."
                            status_icon, status_text, details_text = "❓", "JSON Error", f"Invalid JSON: {snippet}..."
                            current_status_style_for_text = self.error_text
                        except Exception as e: 
                            self.error_share_count += 1
                            status_icon, status_text, details_text = "💥", "Unknown Loop Error", str(e)
                            current_status_style_for_text = self.error_text

                        if log_table.row_count >= max_log_entries and max_log_entries > 0:
                             log_table.rows.pop(0) 

                        if max_log_entries > 0 : 
                            log_table.add_row(
                                str(self.share_attempt_count),
                                timestamp,
                                Text.from_markup(f"{status_icon} [{current_status_style_for_text}]{status_text}[/]"),
                                details_text
                            )
                        
                        live.update(self._generate_live_layout(log_table))
                        time.sleep(share_interval_seconds)

                except KeyboardInterrupt:
                    loop_exited_unexpectedly = False 
                    if current_live_instance: 
                        try:
                            current_live_instance.update(Text(
                                f"\n[{self.warning_text}]Share process interrupted by user. Finalizing...[/]",
                                justify="center"), refresh=True)
                            time.sleep(0.5) 
                        except Exception:
                            pass 
                    raise 

        except KeyboardInterrupt: 
            loop_exited_unexpectedly = False 
            pass 
        except Exception as e: 
            loop_exited_unexpectedly = False 
            if not isinstance(e, KeyboardInterrupt):
                self.stderr.print(
                    Panel(Text.from_markup(
                        f"[{self.error_text}]Critical error in share process: {type(e).__name__}: {e}[/]"
                    ),
                          title=f"[{self.error_text}]Share Loop Error[/]",
                          border_style=self.error_border,
                          title_align="center")
                )
            raise
        finally:
            if loop_exited_unexpectedly:
                self.stderr.print(
                    Panel(Text.from_markup(
                        f"[{self.warning_text}]The share loop seems to have exited unexpectedly.[/]"
                    ), title=f"[{self.warning_text}]Loop Exit Warning[/]", 
                       border_style=self.warning_border,
                       title_align="center")
                )


    def extract_post_id(self):
        patterns = [
            r"pfbid([\w-]+)",
            r"(?:posts|videos|photos|permalink|reel)/(?:[\w.-]+/)?(\d+|pfbid[\w.-]+)", 
            r"(?:story_fbid=|fbid=|v=)(\d+|pfbid[\w.-]+)"
        ]
        extracted_id = None
        for pattern in patterns:
            match = re.search(pattern, self.post_url)
            if match:
                potential_id = match.group(match.lastindex or 1) 
                
                if "pfbid" in pattern and potential_id.startswith("pfbid"):
                    extracted_id = potential_id
                    break
                elif potential_id.startswith("pfbid"): 
                    extracted_id = potential_id
                    break
                elif potential_id.isdigit() and (extracted_id is None or not extracted_id.startswith("pfbid")):
                    extracted_id = potential_id
        if extracted_id:
            self.post_id = extracted_id
            self.stdout.print(
                Panel(Text.from_markup(
                    f"[{self.success_text}]Extracted Post ID: [bold cyan]{self.post_id}[/bold cyan][/]"
                ),
                      title=f"[{self.success_text}]ID Found[/]",
                      border_style=self.success_border, expand=False,
                      title_align="center")
            )
            return

        self._display_message(
            "Could not automatically extract Post ID from URL.",
            title="Input Required",
            style_type="warning")
        self.stdout.print(
            Panel(Text.from_markup(
                "Examples:\n- From `.../posts/pfbidABC...` -> `pfbidABC...`\n- From `.../posts/123...` -> `123...`\n- From `...story_fbid=pfbidXYZ...` -> `pfbidXYZ...`"
            ),
                  title=
                  f"[{self.prompt_bracket}]Manual Post ID Entry[/]", 
                  border_style=self.prompt_bracket, 
                  padding=(0, 1),
                  title_align="center")
            )
        self.post_id = self._prompt_ask("Post ID", prompt_indicator="🆔")
        if not self.post_id:
            self._display_message("Post ID cannot be empty. Exiting.",
                                  title="Invalid Input",
                                  style_type="error")
            sys.exit(1)


    def check_cookies_validity(self):
        if not self.cookies_string:
            self.stdout.print(Text.from_markup(f"[{self.info_text}]No cached cookies found. Proceeding to login.[/]"))
            return False

        session_ok = False
        error_to_report_after_status = None

        with self.stdout.status(
                Text.from_markup(f"[{self.info_text}]Verifying session...[/]"),
                spinner="hearts"):
            headers = self._get_business_page_headers()
            try:
                response = self.session.get("https://www.facebook.com/home.php", 
                                            headers=headers, 
                                            timeout=10,
                                            allow_redirects=False) 
                
                if response.status_code == 200 and ("logout" in response.text.lower() or "mbasic_logout_button" in response.text.lower()):
                    session_ok = True
                elif response.is_redirect or response.status_code in [301, 302, 303, 307, 308]:
                    location = response.headers.get('Location', '').lower()
                    if "login" in location or "checkpoint" in location:
                        error_to_report_after_status = (
                        "Cached session redirected to login/checkpoint. Cookies likely expired.",
                        "Session Invalid", "warning")
                    else:
                        error_to_report_after_status = (
                        f"Session check resulted in a redirect (Status: {response.status_code}, To: {location[:50]}...). Assuming invalid.",
                        "Session Invalid", "warning")
                    session_ok = False
                else: 
                     error_to_report_after_status = (
                    f"Session verification failed. Status: {response.status_code}. URL: {response.url}. Content hint: {response.text[:100]}",
                    "Session Invalid", "warning")
                     session_ok = False

            except requests.exceptions.Timeout:
                error_to_report_after_status = (
                    "Timeout while verifying session.", "Session Check Failed",
                    "error")
                session_ok = False
            except requests.exceptions.RequestException as e:
                error_summary = str(e).splitlines()[0] if str(
                    e).splitlines() else str(e)
                error_to_report_after_status = (
                    f"Network error during session verification: {error_summary}", "Session Check Failed",
                    "error")
                session_ok = False

            time.sleep(0.5) 

        if error_to_report_after_status:
            msg, title, style = error_to_report_after_status
            self._display_message(msg,
                                  title=title,
                                  style_type=style,
                                  panel=True) 
        elif session_ok:
            self.stdout.print(
                Text.from_markup(
                    f" [{self.success_text}]✔ Session active.[/]"))
        else: 
             self._display_message("Session is not active. Please log in.", "Session Invalid", "warning", panel=True)


        return session_ok

    def _display_welcome_message(self):
        self._clear_screen()
        original_author_name = self._get_decrypted_original_author()
        modifier_name = self._get_decrypted_modifier_name()

        premium_status_text = Text("🏅 PREMIUM PLAN ACTIVATED 🏅", style=self.premium_badge, justify="center")
        title_text = Text(f"🚀 Shareb00st3r v2 🚀", style=self.script_name_style, justify="center")
        
        original_credit_text = Text.from_markup(
            f"Made with [red]❤[/red] by [{self.credit_original}]{original_author_name}[/]", 
            style=self.credit_original, 
            justify="center")
        modifier_credit_text = Text.from_markup(
            f"Modified by [{self.credit_modifier}]{modifier_name}[/]", 
            style=self.credit_modifier, 
            justify="center")
        
        separator = Text("─" * 35, style=f"dim {self.premium_main_color}", justify="center")

        welcome_panel_content = Text("\n").join(
            [title_text,
             premium_status_text,
             separator,
             original_credit_text,
             modifier_credit_text]
        )

        welcome_panel = Panel(
            welcome_panel_content,
            title=f"[{self.premium_panel_title}]Welcome[/]",
            border_style=self.premium_panel_border,
            padding=(1, 2), 
            expand=False,
            title_align="center"
        )
        top_padding = 1 
        self.stdout.print(Padding(Align.center(welcome_panel), (top_padding, 0, 2, 0))) 


    def run(self):
        self._display_welcome_message()
        session_initially_valid = False
        if self.cookies_string:
            session_initially_valid = self.check_cookies_validity()
        
        if not session_initially_valid:
            if self.cookies_string: 
                self._display_message("Cached session is invalid or expired. Please log in again.", 
                                      title="Session Expired", style_type="warning")
            self.stdout.print() 
            self._prompt_credentials()
            if not self.fetch_cookies():
                self._display_message("Login failed. Cannot continue.",
                                      title="Fatal Error",
                                      style_type="error")
                sys.exit(1)
        
        self.stdout.print() 
        self.post_url = self._prompt_ask("Facebook Post URL",
                                         prompt_indicator="🔗")
        self.extract_post_id()

        if not self.access_token: 
            if not self.fetch_access_token():
                self._display_message(
                    "Could not obtain access token. Possible reasons:\n"
                    "- Cookies expired (try --clear-session & re-login)\n"
                    "- Facebook API/page structure changed\n"
                    "- Account restrictions or checkpoint",
                    title="Fatal Error: Token Acquisition Failed",
                    style_type="error")
                sys.exit(1)

        self._clear_screen()
        self.perform_share()


if __name__ == "__main__":
    temp_console = Console()

    if "--clear-session" in sys.argv or "--logout" in sys.argv:
        temp_console.print(f"[*] Attempting to clear cached session data from '{session_cache_file}'...")
        try:
            if os.path.exists(session_cache_file):
                os.remove(session_cache_file)
                temp_console.print(f"[green][+][/green] Successfully deleted '{session_cache_file}'.")
                temp_console.print("[*] Cached session has been cleared. You will need to log in again on the next run.")
            else:
                temp_console.print(f"[*] '{session_cache_file}' not found. No cached session to clear.")
        except OSError as e:
            temp_console.print(f"[red][!][/red] Error deleting '{session_cache_file}': {e}")
            temp_console.print("[!] Please try deleting the file manually if necessary.")
        except Exception as e:
            temp_console.print(f"[red][!][/red] An unexpected error occurred while clearing session: {e}")
        sys.exit(0)

    booster = None 
    try:
        booster = ShareBooster()
        booster.run()
    except KeyboardInterrupt:
        if booster: 
            booster.stdout.print("\n") 
            final_summary_text = Text.assemble(
                ("Sharing interrupted by user.\n", f"bold {booster.warning_text}"),
                ("Total Attempted: ", "bold default"),
                (f"{booster.share_attempt_count}", booster.column_attempt),
                (" | Succeeded: ", "bold default"),
                (f"{booster.success_share_count}", booster.success_text),
                (" | Failed: ", "bold default"),
                (f"{booster.error_share_count}", booster.error_text)
            )
            booster.stdout.print(
                Panel(Align.center(final_summary_text),
                      title=f"[{booster.warning_text}]Process Halted[/]",
                      border_style=booster.warning_border,
                      padding=(0,1),
                      title_align="center")
            )
            booster.stdout.print(
                Text.from_markup(
                    f"\n[{booster.info_text}]Exiting Shareb00st3r. Maraming salamat![/] 👋") , justify="center"
            )
        else: 
            temp_console.print("\n[yellow]Process interrupted early. Exiting.[/yellow]")
        sys.exit(0)
    except Exception as e:
        console_err = getattr(booster, 'stderr', temp_console)
        border_err = getattr(booster, 'error_border', 'bold red')
        text_err = getattr(booster, 'error_text', 'bold red')

        console_err.print(
            Panel(Text.from_markup(
                f"[{text_err}]An unexpected critical error occurred: {type(e).__name__}: {e}\n"
                f"This is likely a bug. Please report it if possible.[/]"
            ),
                  title=f"[{text_err}]Unhandled Exception[/]",
                  border_style=border_err,
                  title_align="center")
        )
        import traceback
        console_err.print(f"\n[dim]{traceback.format_exc()}[/dim]")
        sys.exit(1)
