chmod +x *.sh
sudo apt update
sudo apt install jq unzip nmap docker.io xsltproc python3 python3-pip libpangocairo-1.0-0 libx11-xcb1 libxcomposite1 libxcursor1 libxdamage1 libxi6 libxtst6 libnss3 libcups2 libxss1 libxrandr2 libasound2 libatk1.0-0 libgtk-3-0 libgbm-dev libxshmfence-dev
pip3 install --upgrade pip
pip3 install --ignore-installed PyYAML
mkdir resources
git clone https://github.com/ARPSyndicate/kenzerdb.git
cd resources
bash ../chrome.sh
if getopts "b" arg; then
  git clone https://github.com/ARPSyndicate/kenzer-bin.git
  git clone https://github.com/ARPSyndicate/wapiti.git
  cd wapiti
  docker build -t wapiti3 .
  cd ..
  echo "docker run -v \$(pwd):/root/ --rm wapiti3 \$*" > kenzer-bin/wapiti
  chmod +x kenzer-bin/wapiti
  sudo cp kenzer-bin/* /usr/bin/
fi
git clone https://github.com/ARPSyndicate/kenzer-templates.git
git clone https://github.com/ARPSyndicate/freakerdb.git
cd ..
pip3 install -U -r requirements.txt
mkdir ~/.config
mkdir ~/.config/subfinder
cp configs/subfinder.yaml ~/.config/subfinder/provider-config.yaml
cp configs/amass.ini ~/.config/amass-config.ini
./run.sh