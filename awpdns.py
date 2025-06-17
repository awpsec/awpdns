#!/usr/bin/env python3

import argparse
import sys
import dns.resolver
import requests
import socket
import shodan
import pandas as pd
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Any, Optional, Tuple
from ipwhois import IPWhois
import nmap
import os
import shutil
from datetime import datetime
import logging
from tqdm import tqdm
import json
import re
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import time
import vt
import xlsxwriter
from colorama import init, Fore, Style
import configparser

init()

# Configure logging - file gets full format, console gets clean format
file_handler = logging.FileHandler('awpdns.log')
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(logging.Formatter('%(message)s'))

logging.basicConfig(
    level=logging.INFO,
    handlers=[file_handler, console_handler]
)

class DNSRecon:
    def __init__(self, domain: str, output_path: str, scan_mode: str = 'dns', 
                 top_ports: int = None, client_company: str = None, 
                 email_format: str = None, cloud_enum: bool = False):
        self.domain = domain
        self.output_path = output_path
        self.scan_mode = scan_mode  # 'dns', 'passive', or 'active'
        self.top_ports = top_ports
        self.client_company = client_company
        self.email_format = email_format
        self.cloud_enum = cloud_enum
        self.results = []
        
        # Load configuration
        self.config = configparser.ConfigParser()
        config_paths = [
            'awpdns.conf',
            os.path.expanduser('~/.config/awpdns/awpdns.conf'),
            '/etc/awpdns/awpdns.conf'
        ]
        
        config_found = False
        for config_path in config_paths:
            if os.path.exists(config_path):
                self.config.read(config_path)
                config_found = True
                logging.info(f"Loaded configuration from {config_path}")
                break
                
        if not config_found:
            logging.warning("No configuration file found, using environment variables")
        
        self.shodan_api = (self.config.get('api_keys', 'shodan', fallback=None) 
                          or os.getenv('SHODAN_API_KEY'))
        self.vt_api = (self.config.get('api_keys', 'virustotal', fallback=None) 
                      or os.getenv('VT_API_KEY'))
        self.rapid7_api = (self.config.get('api_keys', 'rapid7', fallback=None) 
                          or os.getenv('RAPID7_API_KEY'))
        self.hunter_api = (self.config.get('api_keys', 'hunter', fallback=None) 
                          or os.getenv('HUNTER_API_KEY'))
        
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = self.config.getint('settings', 'timeout', fallback=5)
        self.resolver.lifetime = self.config.getint('settings', 'timeout', fallback=5)
        self.common_ports = self.config.get('settings', 'common_ports', 
            fallback="21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080")
        
        self.session = requests.Session()
        retries = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504]
        )
        self.session.mount('https://', HTTPAdapter(max_retries=retries))
        self.session.mount('http://', HTTPAdapter(max_retries=retries))

    def get_dns_records(self, record_type: str) -> List[Dict[str, Any]]:
        """Query DNS records of specified type."""
        try:
            answers = self.resolver.resolve(self.domain, record_type)
            records = []
            for answer in answers:
                record = {
                    "host": self.domain,
                    "record_type": record_type,
                    "txt_record": "",
                    "domain": self.domain
                }
                
                if record_type == 'NS':
                    record["host"] = str(answer)
                    try:
                        record["ip"] = socket.gethostbyname(str(answer))
                    except socket.gaierror:
                        record["ip"] = ""
                elif record_type == 'MX':
                    mx_host = str(answer.exchange).rstrip('.')
                    record["host"] = f"{answer.preference} {mx_host}"
                    try:
                        record["ip"] = socket.gethostbyname(mx_host)
                    except socket.gaierror:
                        record["ip"] = ""
                elif record_type == 'TXT':
                    record["ip"] = ""
                    record["txt_record"] = str(answer)
                elif record_type == 'A':
                    record["ip"] = str(answer)
                    records.append(record.copy())
                    continue
                else:
                    record["ip"] = str(answer)
                
                records.append(record)
            return records
        except dns.resolver.NoAnswer:
            logging.info(f"No {record_type} records found for {self.domain}")
        except dns.resolver.NXDOMAIN:
            logging.error(f"Domain {self.domain} does not exist")
        except dns.exception.Timeout:
            logging.warning(f"Timeout while querying {record_type} records for {self.domain}")
        except Exception as e:
            logging.warning(f"Error querying {record_type} records: {str(e)}")
        return []

    def get_crt_sh_subdomains(self) -> List[str]:
        """Get subdomains from crt.sh certificate transparency logs."""
        max_attempts = 3
        attempt = 0
        while attempt < max_attempts:
            try:
                url = f"https://crt.sh/?q=%.{self.domain}&output=json"
                response = self.session.get(url, timeout=10)
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        domains = set()
                        for entry in data:
                            name = entry['name_value'].lower()
                            for domain in name.split('\n'):
                                domain = domain.strip()
                                if domain.startswith('*.'):
                                    domain = domain[2:]
                                if domain.endswith(self.domain) and domain != self.domain:
                                    domains.add(domain)
                        logging.info(f"Successfully retrieved {len(domains)} domains from crt.sh")
                        return list(domains)
                    except json.JSONDecodeError:
                        logging.warning("Invalid JSON response from crt.sh")
                else:
                    logging.warning(f"crt.sh returned status code {response.status_code}")
                
            except requests.exceptions.Timeout:
                logging.warning(f"Timeout connecting to crt.sh (attempt {attempt + 1}/{max_attempts})")
            except requests.exceptions.RequestException as e:
                logging.warning(f"Error connecting to crt.sh: {str(e)} (attempt {attempt + 1}/{max_attempts})")
            
            attempt += 1
            if attempt < max_attempts:
                time.sleep(2 ** attempt)
        
        logging.warning("Failed to retrieve data from crt.sh after all attempts")
        return []

    def get_rapid7_subdomains(self) -> List[str]:
        """Get subdomains from Rapid7 Forward DNS dataset."""
        if not self.rapid7_api:
            if self.config.get('settings', 'verbose', fallback='false').lower() == 'true':
                logging.info(f"{Fore.LIGHTBLUE_EX}[*] Skipping Rapid7 enumeration (no API key supplied){Style.RESET_ALL}")
            return []

        discovered_domains = set()
        max_attempts = 3
        attempt = 0

        try:
            socket.gethostbyname('api.rapid7.com')
        except socket.gaierror:
            logging.info(f"{Fore.LIGHTBLUE_EX}[*] Skipping Rapid7 enumeration (cannot resolve api.rapid7.com){Style.RESET_ALL}")
            return []

        while attempt < max_attempts:
            try:
                headers = {
                    'X-Api-Key': self.rapid7_api,
                    'Content-Type': 'application/json'
                }
                
                url = f"https://api.rapid7.com/v1/sonar/fdns/data"
                params = {'query': f'domain: "{self.domain}"'}
                
                # Disable the retry mechanism for this request
                with requests.Session() as session:
                    session.mount('https://', HTTPAdapter(max_retries=0))
                    response = session.get(url, headers=headers, params=params, timeout=30)
                
                if response.status_code == 200:
                    data = response.json()
                    for record in data.get('records', []):
                        name = record.get('name', '').lower()
                        if name.endswith(self.domain) and name != self.domain:
                            discovered_domains.add(name)
                    
                    if discovered_domains:
                        print(f"{Fore.GREEN}[+] Retrieved {len(discovered_domains)} domains from Rapid7{Style.RESET_ALL}")
                    return list(discovered_domains)
                elif response.status_code == 401:
                    logging.info(f"{Fore.LIGHTBLUE_EX}[*] Skipping Rapid7 enumeration (invalid API key supplied){Style.RESET_ALL}")
                    return []
                else:
                    if attempt == max_attempts - 1:
                        logging.info(f"{Fore.LIGHTBLUE_EX}[*] Skipping Rapid7 enumeration (API returned {response.status_code}){Style.RESET_ALL}")
                    
            except requests.exceptions.ConnectionError:
                if attempt == max_attempts - 1:
                    logging.info(f"{Fore.LIGHTBLUE_EX}[*] Skipping Rapid7 enumeration (connection failed){Style.RESET_ALL}")
            except requests.exceptions.Timeout:
                if attempt == max_attempts - 1:
                    logging.info(f"{Fore.LIGHTBLUE_EX}[*] Skipping Rapid7 enumeration (timeout){Style.RESET_ALL}")
            except requests.exceptions.RequestException as e:
                if attempt == max_attempts - 1:
                    logging.info(f"{Fore.LIGHTBLUE_EX}[*] Skipping Rapid7 enumeration ({str(e)}){Style.RESET_ALL}")
            
            attempt += 1
            if attempt < max_attempts:
                time.sleep(2 ** attempt)

        return list(discovered_domains)

    def get_virustotal_subdomains(self) -> List[str]:
        if not self.vt_api:
            if self.config.get('settings', 'verbose', fallback='false').lower() == 'true':
                logging.info(f"{Fore.LIGHTBLUE_EX}[*] Skipping VirusTotal enumeration (no API key supplied){Style.RESET_ALL}")
            return []

        discovered_domains = set()
        try:
            client = vt.Client(self.vt_api)
            try:
                domain_obj = client.get_object(f"/domains/{self.domain}")
                
                try:
                    subdomains = domain_obj.get_attribute('subdomains') or []
                    for subdomain in subdomains:
                        if subdomain.endswith(self.domain) and subdomain != self.domain:
                            discovered_domains.add(subdomain)
                except Exception as e:
                    logging.debug(f"No subdomains found in VirusTotal data: {str(e)}")

                try:
                    resolutions = domain_obj.get_attribute('historical_dns_records') or []
                    for resolution in resolutions:
                        hostname = resolution.get('hostname', '').lower()
                        if hostname.endswith(self.domain) and hostname != self.domain:
                            discovered_domains.add(hostname)
                except Exception as e:
                    logging.debug(f"No historical DNS records found in VirusTotal data: {str(e)}")

            except vt.APIError as e:
                if 'WrongCredentialsError' in str(e):
                    logging.info(f"{Fore.LIGHTBLUE_EX}[*] Skipping VirusTotal enumeration (invalid API key supplied){Style.RESET_ALL}")
                else:
                    logging.info(f"{Fore.LIGHTBLUE_EX}[*] VirusTotal API error: {str(e)}{Style.RESET_ALL}")
            finally:
                client.close()
                
            if discovered_domains:
                print(f"{Fore.GREEN}[+] Retrieved {len(discovered_domains)} domains from VirusTotal{Style.RESET_ALL}")
            
        except Exception as e:
            logging.info(f"{Fore.LIGHTBLUE_EX}[*] Error during VirusTotal enumeration: {str(e)}{Style.RESET_ALL}")
        
        return list(discovered_domains)

    def get_subdomains(self) -> List[Dict[str, Any]]:
        """Get subdomains from all sources and validate them."""
        discovered_subdomains = set()
        
        crt_domains = self.get_crt_sh_subdomains()
        rapid7_domains = self.get_rapid7_subdomains()
        vt_domains = self.get_virustotal_subdomains()
        
        discovered_subdomains.update(crt_domains)
        discovered_subdomains.update(rapid7_domains)
        discovered_subdomains.update(vt_domains)
        
        if self.config.has_section('wordlist'):
            custom_subs = self.config.get('wordlist', 'custom_subdomains', fallback='')
            if custom_subs:
                custom_list = [sub.strip() for sub in custom_subs.split('\n') if sub.strip() and not sub.startswith('#')]
                for sub in custom_list:
                    discovered_subdomains.add(f"{sub}.{self.domain}")
        
        wordlist = [
            "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
            "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
            "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn", "ns3",
            "mail2", "new", "mysql", "old", "lists", "support", "mobile", "mx", "static",
            "docs", "beta", "shop", "sql", "secure", "demo", "cp", "calendar", "wiki",
            "web", "media", "email", "images", "img", "www1", "intranet", "portal", "video",
            "sip", "dns2", "api", "cdn", "stats", "dns1", "ns4", "www3", "dns", "search",
            "staging", "server", "mx1", "chat", "wap", "my", "svn", "mail1", "sites",
            "proxy", "ads", "host", "crm", "cms", "backup", "mx2", "lyncdiscover", "info",
            "apps", "download", "remote", "db", "forums", "store", "relay", "files", "newsletter",
            "app", "live", "owa", "en", "start", "sms", "office", "exchange", "ipv4"
        ]

        for sub in wordlist:
            discovered_subdomains.add(f"{sub}.{self.domain}")

        print(f"{Fore.CYAN}[*] Total unique subdomains discovered: {len(discovered_subdomains)}{Style.RESET_ALL}")
        
        valid_subdomains = []
        max_threads = self.config.getint('settings', 'max_threads', fallback=20)
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_to_subdomain = {
                executor.submit(self.validate_subdomain, subdomain): subdomain 
                for subdomain in discovered_subdomains
            }
            
            for future in tqdm(future_to_subdomain, 
                             desc=f"{Fore.GREEN}[+] Validating subdomains{Style.RESET_ALL}",
                             unit="hosts",
                             unit_scale=True):
                result = future.result()
                if result:
                    valid_subdomains.append(result)

        return valid_subdomains

    def validate_subdomain(self, subdomain: str) -> Optional[Dict[str, Any]]:
        """Validate if a subdomain resolves to an IP."""
        try:
            ip = socket.gethostbyname(subdomain)
            return {
                "host": subdomain,
                "ip": ip,
                "record_type": "A",
                "txt_record": "",
                "domain": self.domain
            }
        except socket.gaierror:
            logging.debug(f"Could not resolve subdomain: {subdomain}")
            return None
        except Exception as e:
            logging.warning(f"Error validating subdomain {subdomain}: {str(e)}")
            return None

    def get_netblock_owner(self, ip: str) -> Tuple[str, str, str]:
        """Get the owner, ASN and range of an IP address's netblock."""
        try:
            obj = IPWhois(ip)
            results = obj.lookup_rdap()
            
            ip_range = results.get('network', {}).get('cidr', '')
            asn = results.get('asn')
            asn_str = f"AS{asn}" if asn else ""
            
            return (
                results.get('asn_description', ''),
                asn_str,
                ip_range
            )
        except Exception as e:
            logging.warning(f"Error getting netblock owner for {ip}: {str(e)}")
            return ('', '', '')

    def clean_banner(self, data: str) -> str:
        """Clean and sanitize banner data."""
        if not data:
            return ""
        
        if isinstance(data, (bytes, bytearray)):
            return ""
        if data.startswith('\x16\x03') or data.startswith('\x80\x80'):
            return ""
            
        if 'HTTP/' in data:
            try:
                status_line = data.split('\n')[0].strip()
                if 'HTTP/' in status_line:
                    return status_line
                return ""
            except:
                return ""

        noise_words = ['cloud', 'auto']
        cleaned = data
        for word in noise_words:
            cleaned = cleaned.replace(word, '').strip()

        cleaned = ''.join(c for c in cleaned if c.isprintable())

        if len(cleaned) > 50:
            cleaned = cleaned[:47] + "..."
            
        return cleaned.strip(' ,:')

    def scan_services(self, ip: str) -> Dict[str, str]:
        """Scan an IP for services using nmap and/or Shodan."""
        services = {
            "http_services": "",
            "remote_services": ""
        }
        
        if self.scan_mode == 'passive':
            if self.shodan_api:
                try:
                    api = shodan.Shodan(self.shodan_api)
                    results = api.host(ip)
                    http_services = set()
                    remote_services = set()
                    
                    for service in results['data']:
                        port = service.get('port')
                        service_str = f"{port}"

                        if service.get('product') and service['product'] != 'auto':
                            service_str += f":{service['product']}"
                            if service.get('version'):
                                service_str += f" {service['version']}"

                        is_http = (
                            service.get('http') is not None or
                            any(s.lower() in str(service).lower() for s in ['http', 'https', 'nginx', 'apache'])
                        )
                        
                        if is_http:
                            http_services.add(service_str)
                        else:
                            remote_services.add(service_str)
                    
                    if http_services:
                        services["http_services"] = ", ".join(sorted(http_services, key=lambda x: int(x.split(':')[0])))
                    if remote_services:
                        services["remote_services"] = ", ".join(sorted(remote_services, key=lambda x: int(x.split(':')[0])))
                        
                except shodan.APIError as e:
                    logging.info(f"{Fore.LIGHTBLUE_EX}[*] Shodan API error for {ip}: {str(e)}{Style.RESET_ALL}")
                except Exception as e:
                    logging.info(f"{Fore.LIGHTBLUE_EX}[*] Error during Shodan lookup for {ip}: {str(e)}{Style.RESET_ALL}")
            
            return services

        elif self.scan_mode == 'active':
            http_services = set()
            remote_services = set()

            if not shutil.which("nmap"):
                logging.info(f"{Fore.LIGHTBLUE_EX}[*] Nmap is not installed. Skipping port scanning{Style.RESET_ALL}")
                return {"http_services": "", "remote_services": ""}

            try:
                nm = nmap.PortScanner()
                if self.top_ports:
                    ports = f"--top-ports {self.top_ports}"
                else:
                    ports = f"-p {self.common_ports}"
                nm.scan(ip, arguments=f'-sS -sV {ports}')
                
                if ip in nm.all_hosts():
                    for port in nm[ip].get('tcp', {}):
                        if nm[ip]['tcp'][port]['state'] == 'open':
                            service = nm[ip]['tcp'][port]
                            service_info = []

                            if service['name'] and service['name'] not in ['tcpwrapped', 'auto']:
                                service_info.append(service['name'])

                            if service.get('product') and service['product'] not in ['auto', service.get('name', '')]:
                                service_info.append(service['product'])

                            if service.get('version'):
                                service_info.append(service['version'])
                            
                            service_str = f"{port}"
                            if service_info:
                                service_str += f":{service_info[0]}"

                            is_http = (
                                service['name'] in ['http', 'https'] or
                                any(s.lower() in str(service_info).lower() for s in ['http', 'https', 'nginx', 'apache'])
                            )
                            
                            if is_http:
                                http_services.add(service_str)
                            else:
                                remote_services.add(service_str)
                        
            except Exception as e:
                logging.warning(f"Error during Nmap scan of {ip}: {str(e)}")

            return {
                "http_services": ", ".join(sorted(http_services, key=lambda x: int(x.split(':')[0]))),
                "remote_services": ", ".join(sorted(remote_services, key=lambda x: int(x.split(':')[0])))
            }
        
        # DNS-only mode - no service scanning
        return services



    def export_to_excel(self, df: pd.DataFrame, output_file: str):
        """Export results to an Excel file with formatting and separate sheets."""
        writer = pd.ExcelWriter(output_file, engine='xlsxwriter')
        workbook = writer.book
        
        # Set default workbook font to Proxima Nova
        workbook.set_properties({
            'title': 'AWPDNS Reconnaissance Report',
            'subject': f'DNS reconnaissance for {self.domain}',
            'author': 'AWPDNS',
            'category': 'Security Assessment'
        })
        
        # Separate email records from other records
        email_records = df[df['Record Type'] == 'EMAIL'].copy()
        other_records = df[df['Record Type'] != 'EMAIL'].copy()
        
        # Use Open Sans Light - confirmed to display as thin/light in Excel
        thin_font_name = 'Open Sans Light'
        
        header_format = workbook.add_format({
            'font_name': thin_font_name,
            'font_size': 11,
            'bold': True,
            'text_wrap': True,
            'valign': 'vcenter',
            'align': 'center',
            'bg_color': '#2F75B5',
            'font_color': 'white',
            'border': 1,
            'border_color': '#1F4E78'
        })
    
        cell_format = workbook.add_format({
            'font_name': thin_font_name,
            'font_size': 10,
            'text_wrap': True,
            'valign': 'vcenter',
            'border': 1,
            'border_color': '#B8CCE4'
        })
    
        alt_row_format = workbook.add_format({
            'font_name': thin_font_name,
            'font_size': 10,
            'text_wrap': True,
            'valign': 'vcenter',
            'bg_color': '#EDF2F7',
            'border': 1,
            'border_color': '#B8CCE4'
        })
        
        # Email header format (different color)
        email_header_format = workbook.add_format({
            'font_name': thin_font_name,
            'font_size': 11,
            'bold': True,
            'text_wrap': True,
            'valign': 'vcenter',
            'align': 'center',
            'bg_color': '#28A745',  # Green for emails
            'font_color': 'white',
            'border': 1,
            'border_color': '#1E7E34'
        })
        

        
        def format_worksheet(worksheet, data, header_fmt):
            """Apply formatting to a worksheet."""
            # Set column widths
            for idx, col in enumerate(data.columns):
                if col in ['TXT Record', 'Owner']:
                    width = 50
                elif col in ['HTTP Services', 'Remote Services']:
                    width = 30
                elif col == 'Name' and 'EMAIL' in str(data['Record Type'].iloc[0] if len(data) > 0 else ''):
                    width = 35  # Wider for email addresses
                else:
                    max_length = max(
                        data[col].astype(str).apply(len).max() if len(data) > 0 else len(col),
                        len(col)
                    )
                    width = min(max_length + 8, 55)
                worksheet.set_column(idx, idx, width)
            
            # Write headers
            for col_num, value in enumerate(data.columns.values):
                worksheet.write(0, col_num, value, header_fmt)
            
            # Write data rows (starting from row 1 since we manually write headers at row 0)
            for row in range(1, len(data) + 1):
                row_format = alt_row_format if row % 2 == 0 else cell_format
                for col in range(len(data.columns)):
                    worksheet.write(row, col, data.iloc[row-1, col], row_format)
            
            # Skip table formatting to preserve our custom fonts and formatting
            # Our custom cell formatting with borders already provides a table-like appearance
            
            worksheet.freeze_panes(1, 0)
        
        # Create DNS Reconnaissance sheet
        if len(other_records) > 0:
            other_records.to_excel(writer, sheet_name='DNS Reconnaissance', index=False, header=False)
            worksheet = writer.sheets['DNS Reconnaissance']
            format_worksheet(worksheet, other_records, header_format)
        
        # Create Email Enumeration sheet
        if len(email_records) > 0:
            # Customize columns for email sheet
            email_df = email_records.copy()
            # Rename columns for better email context
            email_df = email_df.rename(columns={
                'Name': 'Email Address',
                'TXT Record': 'Source/Notes'
            })
            # Remove irrelevant columns for emails
            email_columns = ['Email Address', 'Source/Notes', 'Domain', 'Date Discovered']
            email_df = email_df[email_columns]
            
            email_df.to_excel(writer, sheet_name='Email Enumeration', index=False, header=False)
            worksheet = writer.sheets['Email Enumeration']
            format_worksheet(worksheet, email_df, email_header_format)
        

        writer.close()

    def scrape_client_emails(self) -> List[Dict[str, Any]]:
        """Find email addresses using Hunter.io API with Google dorking as fallback."""
        if not self.client_company:
            return []
        
        emails = []
        discovered_pattern = None
        
        hunter_count = 0
        google_count = 0
        
        # Try Hunter.io first (much more reliable)
        if self.hunter_api:
            logging.info(f"{Fore.CYAN}[*] Searching for emails using Hunter.io API...{Style.RESET_ALL}")
            hunter_emails, discovered_pattern = self._get_hunter_emails()
            emails.extend(hunter_emails)
            hunter_count = len(hunter_emails)
            
            if discovered_pattern:
                print(f"{Fore.CYAN}[*] Hunter.io detected email pattern: {discovered_pattern}{Style.RESET_ALL}")
                # Override user-specified format with Hunter.io's discovered pattern
                effective_format = discovered_pattern
            else:
                effective_format = self.email_format
        else:
            effective_format = self.email_format
        
        # Always try Google dorking for additional emails if we have a format
        if effective_format:
            logging.info(f"{Fore.CYAN}[*] Searching for additional emails using Google dorking...{Style.RESET_ALL}")
            google_emails = self._get_google_dorking_emails(effective_format)
            emails.extend(google_emails)
            google_count = len(google_emails)
        elif not self.hunter_api:
            logging.info(f"{Fore.LIGHTBLUE_EX}[*] No email format specified and no Hunter.io API key{Style.RESET_ALL}")
        
        # Remove duplicates while preserving order
        seen = set()
        unique_emails = []
        for email in emails:
            email_addr = email['host']
            if email_addr not in seen:
                seen.add(email_addr)
                unique_emails.append(email)
        
        # Show final summary
        if unique_emails:
            total_count = len(unique_emails)
            if hunter_count > 0 and google_count > 0:
                print(f"{Fore.GREEN}[+] Found {total_count} total emails ({hunter_count} from Hunter.io, {google_count} from Google dorking){Style.RESET_ALL}")
            elif hunter_count > 0:
                print(f"{Fore.GREEN}[+] Found {total_count} emails from Hunter.io{Style.RESET_ALL}")
            elif google_count > 0:
                print(f"{Fore.GREEN}[+] Found {total_count} emails from Google dorking{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}[+] Found {total_count} email addresses{Style.RESET_ALL}")
        else:
            print(f"{Fore.LIGHTBLUE_EX}[*] No email addresses found. Try checking the company name or domain.{Style.RESET_ALL}")
        
        return unique_emails

    def _get_hunter_emails(self) -> Tuple[List[Dict[str, Any]], str]:
        """Get email addresses from Hunter.io API and discover the email pattern."""
        emails = []
        discovered_pattern = None
        
        try:
            # Hunter.io domain search endpoint
            url = "https://api.hunter.io/v2/domain-search"
            params = {
                'domain': self.domain,
                'api_key': self.hunter_api,
                'limit': 100  # Maximum results
            }
            
            response = self.session.get(url, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                # Extract the email pattern Hunter.io discovered
                if data.get('data') and data['data'].get('pattern'):
                    discovered_pattern = data['data']['pattern']
                
                if data.get('data') and data['data'].get('emails'):
                    for email_data in data['data']['emails']:
                        email_address = email_data.get('value', '')
                        first_name = email_data.get('first_name', '')
                        last_name = email_data.get('last_name', '')
                        confidence = email_data.get('confidence', 0)
                        
                        # Only include emails with reasonable confidence
                        if confidence >= 25 and email_address:
                            source_info = f"Hunter.io (confidence: {confidence}%)"
                            if first_name and last_name:
                                source_info += f" - {first_name} {last_name}"
                            
                            emails.append({
                                "host": email_address,
                                "ip": "",
                                "record_type": "EMAIL",
                                "txt_record": source_info,
                                "domain": self.domain
                            })
                    
                    # Hunter.io results will be summarized in main method
                else:
                    logging.info(f"{Fore.LIGHTBLUE_EX}[*] Hunter.io found no emails for {self.domain}{Style.RESET_ALL}")
                    
            elif response.status_code == 401:
                logging.info(f"{Fore.LIGHTBLUE_EX}[*] Invalid Hunter.io API key{Style.RESET_ALL}")
            elif response.status_code == 429:
                logging.info(f"{Fore.LIGHTBLUE_EX}[*] Hunter.io API rate limit reached{Style.RESET_ALL}")
            else:
                logging.info(f"{Fore.LIGHTBLUE_EX}[*] Hunter.io API returned status {response.status_code}{Style.RESET_ALL}")
                
        except requests.exceptions.RequestException as e:
            logging.info(f"{Fore.LIGHTBLUE_EX}[*] Error connecting to Hunter.io: {str(e)}{Style.RESET_ALL}")
        
        return emails, discovered_pattern

    def _get_google_dorking_emails(self, email_format: str) -> List[Dict[str, Any]]:
        """Get email addresses using Google dorking (fallback method)."""
        emails = []
        found_names = set()
        
        # Google dork queries to find LinkedIn profiles for the company
        dork_queries = [
            f'site:linkedin.com/in/ "{self.client_company}"',
            f'site:linkedin.com/in/ intitle:"{self.client_company}"',
            f'site:linkedin.com "at {self.client_company}"',
            f'site:linkedin.com "{self.client_company}" -pub -dir',
        ]
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        
        for query in dork_queries:
            try:
                # Use Google search with the dork query
                search_url = f"https://www.google.com/search"
                params = {
                    'q': query,
                    'num': 50,  # Number of results per page
                    'start': 0
                }
                
                time.sleep(2)  # Rate limiting to avoid being blocked
                response = self.session.get(search_url, params=params, headers=headers, timeout=10)
                
                if response.status_code == 200:
                    # Parse the HTML to extract LinkedIn profile information
                    html_content = response.text
                    names = self._extract_names_from_google_results(html_content)
                    found_names.update(names)
                    
                elif response.status_code == 429:
                    logging.info(f"{Fore.LIGHTBLUE_EX}[*] Rate limited by Google, stopping dorking{Style.RESET_ALL}")
                    break
                    
            except requests.exceptions.RequestException as e:
                logging.debug(f"Error with Google dork query '{query}': {str(e)}")
                continue
        
        # Generate emails from found names
        domain_part = self.domain
        if '@' in email_format:
            domain_part = email_format.split('@')[1]
        
        generated_count = 0
        for full_name in found_names:
            try:
                if not full_name or len(full_name.split()) < 2:
                    continue
                    
                name_parts = full_name.split()
                first = name_parts[0]
                last = name_parts[-1]  # Take last part as surname
                
                # Clean names - remove titles, suffixes, etc.
                first = self._clean_name(first)
                last = self._clean_name(last)
                
                if not first or not last or len(first) < 2 or len(last) < 2:
                    continue
                
                # Generate email based on format
                email_address = self._generate_email_address(first, last, email_format)
                full_email = f"{email_address}@{domain_part}"
                
                emails.append({
                    "host": full_email,
                    "ip": "",
                    "record_type": "EMAIL",
                    "txt_record": f"Google dorking - LinkedIn profile: {full_name}",
                    "domain": self.domain
                })
                generated_count += 1
                
            except Exception as e:
                logging.debug(f"Error generating email for {full_name}: {str(e)}")
                continue
        
        # Google dorking results will be summarized in main method
        
        return emails

    def _extract_names_from_google_results(self, html_content: str) -> set:
        """Extract names from Google search results containing LinkedIn profiles."""
        names = set()
        
        # Improved patterns for LinkedIn profile names in Google search results
        patterns = [
            # LinkedIn profile titles in search results - more specific
            r'<h3[^>]*>([A-Z][a-z]+ [A-Z][a-z]+(?:\s[A-Z][a-z]+)*)\s*[-|•]\s*[^<]*LinkedIn</h3>',
            r'<h3[^>]*>([A-Z][a-z]+ [A-Z][a-z]+(?:\s[A-Z][a-z]+)*)\s*\|\s*LinkedIn</h3>',
            
            # Profile names in LinkedIn URLs and snippets
            r'linkedin\.com/in/[^"]*[">][^<]*>([A-Z][a-z]+ [A-Z][a-z]+(?:\s[A-Z][a-z]+)*)</a>',
            
            # Names followed by job titles or company mentions
            r'([A-Z][a-z]+ [A-Z][a-z]+(?:\s[A-Z][a-z]+)*)\s*[-–]\s*[A-Z][a-z]+.*?at\s+' + re.escape(self.client_company),
            r'([A-Z][a-z]+ [A-Z][a-z]+(?:\s[A-Z][a-z]+)*)\s*,\s*[A-Z][a-z]+.*?' + re.escape(self.client_company),
            
            # Direct name patterns with proper capitalization
            r'View\s+([A-Z][a-z]+ [A-Z][a-z]+(?:\s[A-Z][a-z]+)*)\'s\s+profile\s+on\s+LinkedIn',
            r'Connect\s+with\s+([A-Z][a-z]+ [A-Z][a-z]+(?:\s[A-Z][a-z]+)*)\s+on\s+LinkedIn',
        ]
        
        # Common phrases to exclude (not real names)
        exclude_phrases = {
            'click here', 'view profile', 'connect with', 'follow on', 'message on',
            'linkedin profile', 'see more', 'learn more', 'read more', 'show more',
            'get started', 'sign up', 'log in', 'join now', 'try free', 'contact us',
            'about us', 'privacy policy', 'terms service', 'help center', 'support team',
            'customer service', 'sales team', 'marketing team', 'hr department',
            'job search', 'career opportunities', 'post job', 'hire talent'
        }
        
        # Common job titles that aren't names
        job_titles = {
            'chief executive', 'chief technology', 'chief financial', 'chief marketing',
            'senior developer', 'software engineer', 'project manager', 'product manager',
            'data analyst', 'business analyst', 'sales representative', 'account manager',
            'human resources', 'customer success', 'quality assurance', 'security analyst'
        }
        
        for pattern in patterns:
            matches = re.findall(pattern, html_content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                # Clean up the extracted name
                name = match.strip()
                name = re.sub(r'\s+', ' ', name)  # Normalize whitespace
                name = re.sub(r'[^\w\s\-\'\.]', '', name)  # Keep only letters, spaces, hyphens, apostrophes, dots
                
                # Convert to title case for consistency
                name = ' '.join(word.capitalize() for word in name.split())
                
                # Validate the name
                if self._is_valid_person_name(name, exclude_phrases, job_titles):
                    names.add(name)
        
        return names

    def _is_valid_person_name(self, name: str, exclude_phrases: set, job_titles: set) -> bool:
        """Validate if the extracted text is likely a real person's name."""
        if not name or len(name) < 4:
            return False
        
        name_lower = name.lower()
        
        # Check against excluded phrases
        for phrase in exclude_phrases:
            if phrase in name_lower:
                return False
        
        # Check against job titles
        for title in job_titles:
            if title in name_lower:
                return False
        
        # Split into parts
        parts = name.split()
        
        # Must have at least 2 parts (first and last name)
        if len(parts) < 2:
            return False
        
        # Each part should be at least 2 characters and start with capital letter
        for part in parts[:3]:  # Check first 3 parts max
            if len(part) < 2 or not part[0].isupper():
                return False
            
            # Should contain only letters (and maybe apostrophes/hyphens)
            if not re.match(r'^[A-Za-z\'\-]+$', part):
                return False
        
        # Check for common non-name patterns
        invalid_patterns = [
            r'\d',  # Contains numbers
            r'^(Mr|Mrs|Ms|Dr|Prof)\s',  # Starts with title
            r'\s(Jr|Sr|II|III|IV|Ph\.?D|M\.?D|CEO|CTO|CFO)$',  # Ends with suffix/title
            r'^(The|An|A)\s',  # Starts with articles
            r'(Team|Department|Group|Division)$',  # Ends with organizational terms
        ]
        
        for pattern in invalid_patterns:
            if re.search(pattern, name, re.IGNORECASE):
                return False
        
        # Additional validation: check if it looks like a real name
        # Common first names pattern (at least some vowels)
        first_name = parts[0].lower()
        if not re.search(r'[aeiou]', first_name):
            return False
        
        # Last name should also have vowels (most real surnames do)
        last_name = parts[-1].lower()
        if not re.search(r'[aeiou]', last_name):
            return False
        
        return True

    def _clean_name(self, name: str) -> str:
        """Clean and normalize name parts."""
        # Remove common titles and suffixes
        prefixes = ['mr', 'mrs', 'ms', 'dr', 'prof', 'sir', 'dame']
        suffixes = ['jr', 'sr', 'ii', 'iii', 'iv', 'phd', 'md', 'cpa', 'ceo', 'cto', 'cfo']
        
        name = name.lower().strip()
        name = re.sub(r'[^\w]', '', name)  # Remove non-alphanumeric
        
        if name in prefixes or name in suffixes:
            return ''
        
        return name

    def _generate_email_address(self, first: str, last: str, email_format: str) -> str:
        """Generate email address based on the provided format."""
        email_local = email_format.split('@')[0] if '@' in email_format else email_format
        
        # Create a mapping of all possible substitutions
        substitutions = {
            '{f}': first[0].lower() if first else '',          # First initial
            '{l}': last[0].lower() if last else '',            # Last initial  
            '{first}': first.lower() if first else '',         # Full first name
            '{last}': last.lower() if last else '',            # Full last name
        }
        
        # Apply all substitutions
        result = email_local
        for pattern, replacement in substitutions.items():
            result = result.replace(pattern, replacement)
        
        # If no substitutions were made, default to {f}{l} format
        if result == email_local and '{' not in email_local:
            result = f"{first[0].lower()}{last.lower()}" if first and last else email_local
        
        return result

    def enumerate_cloud_resources(self) -> List[Dict[str, Any]]:
        """Enumerate cloud resources for the domain."""
        if not self.cloud_enum:
            return []
        
        cloud_resources = []
        domain_base = self.domain.split('.')[0]
        
        # Common cloud resource patterns
        cloud_patterns = [
            # Azure
            f"{domain_base}.blob.core.windows.net",
            f"{domain_base}.azurewebsites.net",
            f"{domain_base}.cloudapp.azure.com",
            f"{domain_base}.azurehdinsight.net",
            f"{domain_base}.azureedge.net",
            f"{domain_base}.database.windows.net",
            
            # AWS
            f"{domain_base}.s3.amazonaws.com",
            f"{domain_base}.s3-website-us-east-1.amazonaws.com",
            f"{domain_base}.s3-website.us-east-1.amazonaws.com",
            f"{domain_base}.amazonaws.com",
            f"{domain_base}.awsapps.com",
            f"{domain_base}.elasticbeanstalk.com",
            
            # Google Cloud
            f"{domain_base}.storage.googleapis.com",
            f"{domain_base}.appspot.com",
            f"{domain_base}.googleusercontent.com",
            f"{domain_base}.cloudfunctions.net",
            f"{domain_base}.run.app",
            
            # SharePoint/Office 365
            f"{domain_base}.sharepoint.com",
            f"{domain_base}-my.sharepoint.com",
            f"{domain_base}.onmicrosoft.com",
            
            # Other cloud services
            f"{domain_base}.herokuapp.com",
            f"{domain_base}.github.io",
            f"{domain_base}.digitaloceanspaces.com",
        ]
        
        print(f"{Fore.CYAN}[*] Enumerating cloud resources...{Style.RESET_ALL}")
        
        def check_cloud_resource(resource_url):
            try:
                response = self.session.head(resource_url, timeout=5)
                if response.status_code in [200, 403, 301, 302]:
                    return {
                        "host": resource_url,
                        "ip": "",
                        "record_type": "CLOUD",
                        "txt_record": f"HTTP {response.status_code}",
                        "domain": self.domain
                    }
            except:
                pass
            return None
        
        max_threads = self.config.getint('settings', 'max_threads', fallback=20)
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_to_resource = {
                executor.submit(check_cloud_resource, f"https://{pattern}"): pattern 
                for pattern in cloud_patterns
            }
            
            for future in tqdm(future_to_resource, 
                             desc=f"{Fore.GREEN}[+] Checking cloud resources{Style.RESET_ALL}",
                             unit="resources",
                             unit_scale=True):
                result = future.result()
                if result:
                    cloud_resources.append(result)
        
        if cloud_resources:
            print(f"{Fore.GREEN}[+] Found {len(cloud_resources)} accessible cloud resources{Style.RESET_ALL}")
        
        return cloud_resources

def main():
    parser = argparse.ArgumentParser(description='reconnaissance tool for dns/whois/portscan')
    parser.add_argument('-d', '--domain', required=True, help='target domain')
    parser.add_argument('-o', '--output', help='output directory for results')
    parser.add_argument('-p', '--passive', action='store_true', help='passive mode - uses Shodan API if available')
    parser.add_argument('-a', '--active', action='store_true', help='active mode - includes nmap port scanning')
    parser.add_argument('-t', '--top-ports', type=int, help='scan top ports instead of common ports (requires -a)')
    parser.add_argument('-v', '--verbose', action='store_true', help='show detailed progress and results')
    parser.add_argument('-client', '--client', help='Client company name for email enumeration using Hunter.io API')
    parser.add_argument('-email', '--email-format', help='email format for fallback generation - Hunter.io pattern takes precedence (e.g., {f}{l}@domain.com, {first}.{last}@domain.com, {f}.{l}@domain.com)')
    parser.add_argument('-cloud', '--cloud-enum', action='store_true', help='enumerate cloud resources')
    args = parser.parse_args()

    # Determine scan mode
    scan_mode = 'dns'  # Default to DNS-only mode
    if args.passive and args.active:
        print(f"{Fore.RED}[-] Cannot use both passive (-p) and active (-a) modes simultaneously{Style.RESET_ALL}")
        sys.exit(1)
    elif args.passive:
        scan_mode = 'passive'
    elif args.active:
        scan_mode = 'active'
    
    if args.top_ports and not args.active:
        print(f"{Fore.RED}[-] --top-ports flag requires active mode (-a){Style.RESET_ALL}")
        sys.exit(1)

    if args.output:
        os.makedirs(args.output, exist_ok=True)

    recon = DNSRecon(
        domain=args.domain,
        output_path=args.output or '.',
        scan_mode=scan_mode,
        top_ports=args.top_ports,
        client_company=args.client,
        email_format=args.email_format,
        cloud_enum=args.cloud_enum
    )

    print(f"\n{Fore.CYAN}[*] Starting DNS reconnaissance for {Fore.YELLOW}{args.domain}{Style.RESET_ALL}")

    results = []
    total_records = 0
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']
    
    with tqdm(total=len(record_types), 
              desc=f"{Fore.GREEN}[+] Gathering DNS records{Style.RESET_ALL}",
              disable=args.verbose,
              unit="types") as pbar:
        for i, record_type in enumerate(record_types, 1):
            records = recon.get_dns_records(record_type)
            results.extend(records)
            total_records += len(records)
            if args.verbose:
                print(f"[{i}/{len(record_types)}] Found {len(records)} {record_type} records")
            pbar.update(1)
    
    if not args.verbose:
        print(f"{Fore.GREEN}[+] Found {total_records} DNS records{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}[*] Enumerating subdomains...{Style.RESET_ALL}")
    subdomains = recon.get_subdomains()
    results.extend(subdomains)
    
    if not args.verbose:
        print(f"{Fore.GREEN}[+] Found {len(subdomains)} valid subdomains{Style.RESET_ALL}")

    # Client email enumeration
    if args.client:
        print(f"\n{Fore.CYAN}[*] Enumerating client emails...{Style.RESET_ALL}")
        client_emails = recon.scrape_client_emails()
        results.extend(client_emails)
        if not args.verbose:
            print(f"{Fore.GREEN}[+] Found {len(client_emails)} email addresses{Style.RESET_ALL}")

    # Cloud resource enumeration
    if args.cloud_enum:
        cloud_resources = recon.enumerate_cloud_resources()
        results.extend(cloud_resources)
        if not args.verbose and cloud_resources:
            print(f"{Fore.GREEN}[+] Found {len(cloud_resources)} cloud resources{Style.RESET_ALL}")

    if results:
        print(f"\n{Fore.CYAN}[*] Gathering additional information...{Style.RESET_ALL}")
        df = pd.DataFrame(results)

        df = df.rename(columns={'host': 'Name'})
        if 'txt_record' not in df.columns:
            df['txt_record'] = ''
        df = df.rename(columns={'txt_record': 'TXT Record'})
        if 'domain' not in df.columns:
            df['domain'] = args.domain
        df = df.rename(columns={
            'record_type': 'Record Type',
            'domain': 'Domain',
            'ip': 'IP'
        })
        
        def is_valid_ip(ip):
            if not ip:
                return False
            try:
                ip = ip.strip('. ')
                ip = ip.split()[0]
                # Skip if it contains domain-like patterns (dots with letters)
                if '.' in ip and any(c.isalpha() for c in ip):
                    return False
                socket.inet_pton(socket.AF_INET, ip)
                return True
            except (socket.error, ValueError):
                try:
                    socket.inet_pton(socket.AF_INET6, ip)
                    return True
                except (socket.error, ValueError):
                    return False

        df['IP'] = df['IP'].astype(str).apply(lambda x: x.strip('. ').split()[0] if x else '')

        # Filter to only valid IP addresses (exclude hostnames, empty values, etc.)
        unique_ips = [ip for ip in df['IP'].unique() if is_valid_ip(ip)]
        ip_info = {}
        
        with tqdm(total=len(unique_ips), 
                 desc=f"{Fore.GREEN}[+] Processing IPs{Style.RESET_ALL}",
                 unit="IPs",
                 unit_scale=True) as pbar:
            for ip in unique_ips:
                owner, asn, ip_range = recon.get_netblock_owner(ip)
                
                # Only scan services if in passive or active mode
                if scan_mode in ['passive', 'active']:
                    services = recon.scan_services(ip)
                else:
                    services = {'http_services': '', 'remote_services': ''}
                
                ip_info[ip] = {
                    'Owner': owner,
                    'ASN': asn,
                    'Range': ip_range,
                    'HTTP Services': services['http_services'],
                    'Remote Services': services['remote_services']
                }
                pbar.update(1)

        for ip in df['IP'].unique():
            if ip not in ip_info:
                ip_info[ip] = {
                    'Owner': 'N/A',
                    'ASN': 'N/A',
                    'Range': 'N/A',
                    'HTTP Services': 'N/A',
                    'Remote Services': 'N/A'
                }

        df['Owner'] = df['IP'].map(lambda x: ip_info[x]['Owner'])
        df['ASN'] = df['IP'].map(lambda x: ip_info[x]['ASN'])
        df['Range'] = df['IP'].map(lambda x: ip_info[x]['Range'])
        df['HTTP Services'] = df['IP'].map(lambda x: ip_info[x]['HTTP Services'])
        df['Remote Services'] = df['IP'].map(lambda x: ip_info[x]['Remote Services'])

        df['Date Discovered'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        df = df[[
            'Record Type',
            'Name',
            'IP',
            'TXT Record',
            'Domain',
            'ASN',
            'Range',
            'Owner',
            'HTTP Services',
            'Remote Services',
            'Date Discovered'
        ]]

        df = df.sort_values('Record Type')

        if args.output:
            # Clean domain name for filename (remove TLD)
            domain_name = args.domain.split('.')[0]
            csv_file = os.path.join(args.output, f'awpdns_{domain_name}.csv')
            excel_file = os.path.join(args.output, f'awpdns_{domain_name}.xlsx')
            
            print(f"\n{Fore.GREEN}[+] Saving results...{Style.RESET_ALL}")
            df.to_csv(csv_file, index=False)
            recon.export_to_excel(df, excel_file)
            print(f"{Fore.GREEN}[+] Results saved to:{Style.RESET_ALL}")
            print(f"    CSV: {csv_file}")
            print(f"    Excel: {excel_file}")

        if args.verbose:
            print("\nReconnaissance Results:")
            print(df.to_string())
        else:
            print(f"\n{Fore.GREEN}[+] Reconnaissance completed successfully!{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Use -v flag to see detailed results{Style.RESET_ALL}")
    else:
        print(f"\n{Fore.RED}[-] No results found.{Style.RESET_ALL}")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[-] Operation cancelled by user{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"An unexpected error occurred: {str(e)}")
        print(f"\n{Fore.RED}[-] An error occurred. Check awpdns.log for details{Style.RESET_ALL}")
        sys.exit(1)
