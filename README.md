# awpdns
dns/whois/portscan tool

usage: awpdns.py [-h] -d DOMAIN [-o OUTPUT] [-a] [-p] [-v]

dns recon tool

options:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        target domain
  -o OUTPUT, --output OUTPUT
                        output directory for results
  -a, --all-ports       scan all ports instead of common ports
  -p, --passive         passive mode - no port scanning
  -v, --verbose         show detailed progress and results


git clone
run the setup
activate env

add any API keys to the .conf

run the tool

# WARNING: BY DEFAULT THIS PORT SCANS! USE -p FOR PASSIVE RECON
