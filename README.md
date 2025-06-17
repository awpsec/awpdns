# awpdns

usage: awpdns.py [-h] -d DOMAIN [-o OUTPUT] [-p] [-a] [-t TOP_PORTS] [-v] [-client CLIENT] [-email EMAIL_FORMAT] [-cloud]

reconnaissance tool for dns/whois/portscan

```
options:
  -h, --help            show this help message and exit
  -d, --domain DOMAIN   target domain
  -o, --output OUTPUT   output directory for results
  -p, --passive         passive mode - uses Shodan API if available
  -a, --active          active mode - includes nmap port scanning
  -t, --top-ports TOP_PORTS
                        scan top ports instead of common ports (requires -a)
  -v, --verbose         show detailed progress and results
  -client, --client CLIENT
                        Client company name for output name + email enumeration using hunter.io API
  -email, --email-format EMAIL_FORMAT
                        email format for fallback google dorking generation - hunter.io pattern takes precedence (e.g., {f}{l}@domain.com, {first}.{last}@domain.com,
                        {f}.{l}@domain.com)
  -cloud, --cloud-enum  enumerate cloud resources
```

git clone the repo
run the setup.sh script to create virtual environment, and install requirements inside of it
add any API keys to the awpdns.conf config file
activate the environment 

run the tool:

i.e. enumerate dns, whois, emails, cloud resources and shodan portscanning for client 'Example Company'

`python3 awpdns.py -d example.xyz -client 'Example Company' -email {f}.{last}@example.xyz -o example -cloud -p`
