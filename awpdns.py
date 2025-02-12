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

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('awpdns.log'),
        logging.StreamHandler()
    ]
)

class DNSRecon:
    def __init__(self, domain: str, output_path: str, scan_all_ports: bool = False, passive: bool = False):
        self.domain = domain
        self.output_path = output_path
        self.scan_all_ports = scan_all_ports
        self.passive = passive
        self.results = []
        
        # Load configuration
        self.config = configparser.ConfigParser()
        config_paths = [
            'awpdns.conf',  # Current directory
            os.path.expanduser('~/.config/awpdns/awpdns.conf'),  # User's config directory
            '/etc/awpdns/awpdns.conf'  # System-wide config
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
                logging.info(f"{Fore.YELLOW}[*] Skipping Rapid7 enumeration (no API key){Style.RESET_ALL}")
            return []

        discovered_domains = set()
        max_attempts = 3
        attempt = 0

        try:
            socket.gethostbyname('api.rapid7.com')
        except socket.gaierror:
            logging.info(f"{Fore.YELLOW}[*] Skipping Rapid7 enumeration (cannot resolve api.rapid7.com){Style.RESET_ALL}")
            return []

        while attempt < max_attempts:
            try:
                headers = {
                    'X-Api-Key': self.rapid7_api,
                    'Content-Type': 'application/json'
                }
                
                url = f"https://api.rapid7.com/v1/sonar/fdns/data"
                params = {'query': f'domain: "{self.domain}"'}
                
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
                        logging.info(f"{Fore.GREEN}[+] Retrieved {len(discovered_domains)} domains from Rapid7{Style.RESET_ALL}")
                    return list(discovered_domains)
                elif response.status_code == 401:
                    logging.info(f"{Fore.YELLOW}[*] Skipping Rapid7 enumeration (invalid API key){Style.RESET_ALL}")
                    return []
                else:
                    if attempt == max_attempts - 1:
                        logging.info(f"{Fore.YELLOW}[*] Skipping Rapid7 enumeration (API returned {response.status_code}){Style.RESET_ALL}")
                    
            except requests.exceptions.ConnectionError:
                if attempt == max_attempts - 1:
                    logging.info(f"{Fore.YELLOW}[*] Skipping Rapid7 enumeration (connection failed){Style.RESET_ALL}")
            except requests.exceptions.Timeout:
                if attempt == max_attempts - 1:
                    logging.info(f"{Fore.YELLOW}[*] Skipping Rapid7 enumeration (timeout){Style.RESET_ALL}")
            except requests.exceptions.RequestException as e:
                if attempt == max_attempts - 1:
                    logging.info(f"{Fore.YELLOW}[*] Skipping Rapid7 enumeration ({str(e)}){Style.RESET_ALL}")
            
            attempt += 1
            if attempt < max_attempts:
                time.sleep(2 ** attempt)

        return list(discovered_domains)

    def get_virustotal_subdomains(self) -> List[str]:
        if not self.vt_api:
            if self.config.get('settings', 'verbose', fallback='false').lower() == 'true':
                logging.info(f"{Fore.YELLOW}[*] Skipping VirusTotal enumeration (no API key){Style.RESET_ALL}")
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
                    logging.warning(f"{Fore.YELLOW}[!] Invalid VirusTotal API key{Style.RESET_ALL}")
                else:
                    logging.warning(f"{Fore.YELLOW}[!] VirusTotal API error: {str(e)}{Style.RESET_ALL}")
            finally:
                client.close()
                
            if discovered_domains:
                logging.info(f"{Fore.GREEN}[+] Retrieved {len(discovered_domains)} domains from VirusTotal{Style.RESET_ALL}")
            
        except Exception as e:
            logging.warning(f"{Fore.YELLOW}[!] Error during VirusTotal enumeration: {str(e)}{Style.RESET_ALL}")
        
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

        logging.info(f"Total unique subdomains discovered: {len(discovered_subdomains)}")
        
        valid_subdomains = []
        max_threads = self.config.getint('settings', 'max_threads', fallback=20)
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_to_subdomain = {
                executor.submit(self.validate_subdomain, subdomain): subdomain 
                for subdomain in discovered_subdomains
            }
            
            for future in tqdm(future_to_subdomain, desc=f"{Fore.GREEN}[+] Validating subdomains{Style.RESET_ALL}"):
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
        if self.passive:
            services = {
                "http_services": "",
                "remote_services": ""
            }
            
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
                    logging.warning(f"{Fore.YELLOW}[!] Shodan API error for {ip}: {str(e)}{Style.RESET_ALL}")
                except Exception as e:
                    logging.warning(f"{Fore.YELLOW}[!] Error during Shodan lookup for {ip}: {str(e)}{Style.RESET_ALL}")
            
            return services

        http_services = set()
        remote_services = set()
        
        if not shutil.which("nmap"):
            logging.warning("Nmap is not installed. Skipping port scanning.")
            return {"http_services": "", "remote_services": ""}

        try:
            nm = nmap.PortScanner()
            ports = "-p-" if self.scan_all_ports else f"-p {self.common_ports}"
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

    def export_to_excel(self, df: pd.DataFrame, output_file: str):
        """Export results to an Excel file with formatting."""
        writer = pd.ExcelWriter(output_file, engine='xlsxwriter')
        df.to_excel(writer, sheet_name='DNS Reconnaissance', index=False)
        
        workbook = writer.book
        worksheet = writer.sheets['DNS Reconnaissance']
        
        # Add formats
        header_format = workbook.add_format({
            'bold': True,
            'text_wrap': True,
            'valign': 'top',
            'bg_color': '#D9E1F2',
            'border': 1
        })
        
        cell_format = workbook.add_format({
            'text_wrap': True,
            'valign': 'top',
            'border': 1
        })
        
        for idx, col in enumerate(df.columns):
            max_length = max(
                df[col].astype(str).apply(len).max(),
                len(col)
            )
            worksheet.set_column(idx, idx, min(max_length + 2, 50))
        
        for col_num, value in enumerate(df.columns.values):
            worksheet.write(0, col_num, value, header_format)
        
        for row in range(1, len(df) + 1):
            for col in range(len(df.columns)):
                worksheet.write(row, col, df.iloc[row-1, col], cell_format)
        
        writer.close()

def main():
    parser = argparse.ArgumentParser(description='DNS reconnaissance tool')
    parser.add_argument('-d', '--domain', required=True, help='Target domain')
    parser.add_argument('-o', '--output', help='Output directory for results')
    parser.add_argument('-a', '--all-ports', action='store_true', help='Scan all ports instead of common ports')
    parser.add_argument('-p', '--passive', action='store_true', help='Passive mode - no port scanning')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show detailed progress and results')
    args = parser.parse_args()

    if args.output:
        os.makedirs(args.output, exist_ok=True)

    recon = DNSRecon(
        domain=args.domain,
        output_path=args.output or '.',
        scan_all_ports=args.all_ports,
        passive=args.passive
    )

    print(f"\n{Fore.CYAN}[*] Starting DNS reconnaissance for {Fore.YELLOW}{args.domain}{Style.RESET_ALL}")
    
    results = []
    total_records = 0
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']
    
    with tqdm(total=len(record_types), 
              desc=f"{Fore.GREEN}[+] Gathering DNS records{Style.RESET_ALL}",
              disable=args.verbose) as pbar:
        for record_type in record_types:
            records = recon.get_dns_records(record_type)
            results.extend(records)
            total_records += len(records)
            if args.verbose:
                print(f"Found {len(records)} {record_type} records")
            pbar.update(1)
    
    if not args.verbose:
        print(f"{Fore.GREEN}[+] Found {total_records} DNS records{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}[*] Enumerating subdomains...{Style.RESET_ALL}")
    subdomains = recon.get_subdomains()
    results.extend(subdomains)
    
    if not args.verbose:
        print(f"{Fore.GREEN}[+] Found {len(subdomains)} valid subdomains{Style.RESET_ALL}")

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
                socket.inet_pton(socket.AF_INET, ip)
                return True
            except (socket.error, ValueError):
                try:
                    socket.inet_pton(socket.AF_INET6, ip)
                    return True
                except (socket.error, ValueError):
                    return False
            
        df['IP'] = df['IP'].astype(str).apply(lambda x: x.strip('. ').split()[0] if x else '')
        
        unique_ips = [ip for ip in df['IP'].unique() if ':' not in ip]  # Simple check to exclude IPv6
        ip_info = {}
        
        with tqdm(total=len(unique_ips), 
                 desc=f"{Fore.GREEN}[+] Scanning IPs{Style.RESET_ALL}") as pbar:
            for ip in unique_ips:
                owner, asn, ip_range = recon.get_netblock_owner(ip)
                services = recon.scan_services(ip)
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
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            csv_file = os.path.join(args.output, f'dns_recon_{timestamp}.csv')
            excel_file = os.path.join(args.output, f'dns_recon_{timestamp}.xlsx')
            
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
