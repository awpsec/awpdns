#!/bin/bash

if ! command -v python3 &> /dev/null; then
    echo "Python3 is not installed. Please install Python3 first."
    exit 1
fi

rm -rf dns-env

echo "Creating virtual environment dns-env..."
python3 -m venv dns-env

echo "Activating virtual environment..."
source dns-env/bin/activate

echo "Upgrading pip..."
python3 -m pip install --upgrade pip

if [ "$EUID" -eq 0 ]; then
    echo "Installing system dependencies..."
    apt-get update
    apt-get install -y nmap
else
    echo "Warning: Not running as root. Please run 'sudo apt-get install nmap' manually if not already installed."
fi

echo "Installing Python dependencies..."
pip install -r requirements.txt



echo "Creating configuration file..."
if [ ! -f "awpdns.conf" ]; then
    cat > awpdns.conf << EOL
[api_keys]
shodan = your_shodan_key_here
virustotal = your_virustotal_key_here
rapid7 = your_rapid7_key_here
hunter = your_hunter_io_key_here

[settings]
common_ports = 21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080
max_threads = 20
timeout = 5



[wordlist]
# Add custom subdomains to check (one per line)
custom_subdomains = 
    dev
    stage
    test
    uat
    # Add more here
EOL
    echo "Created awpdns.conf"
else
    echo "Configuration file already exists"
fi

echo -e "\nSetup completed successfully!"
echo -e "\nNotes:"
echo "1. Edit awpdns.conf to add your API keys and customize settings"
echo "2. Or set environment variables:"
echo "   export SHODAN_API_KEY='your-api-key'"
echo "   export VT_API_KEY='your-api-key'"
echo "   export RAPID7_API_KEY='your-api-key'"
echo "   export HUNTER_API_KEY='your-api-key'"
echo -e "\nUsage example:"
echo "python3 awpdns.py -d example.com -o ~/output/example"
echo "python3 awpdns.py -d example.com -o ~/output/example -a  # scan all ports"
echo "python3 awpdns.py -d example.com -o ~/output/example -p  # passive mode"
echo "python3 awpdns.py -d example.com -o ~/output/example -v  # verbose output"
