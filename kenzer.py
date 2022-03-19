# imports
import zulip
import time
from datetime import datetime
import os
import sys
from chatterbot import ChatBot
from chatterbot.trainers import ChatterBotCorpusTrainer
from configparser import ConfigParser
import validators
import tldextract
import ipaddress

# core modules
from modules import enumerator
from modules import scanner
from modules import monitor

# colors
BLUE = '\033[94m'
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
CLEAR = '\x1b[0m'

# configs
try:
    conf = "configs/kenzer.conf"
    config = ConfigParser()
    with open(conf) as f:
        config.read_file(f, conf)
    _BotMail = config.get("kenzer", "email")
    _Site = config.get("kenzer", "site")
    _APIKey = config.get("kenzer", "key")
    _uploads = config.get("kenzer", "uploads")
    _subscribe = config.get("kenzer", "subscribe")
    _kenzer = config.get("kenzer", "path")
    _logging = config.get("kenzer", "logging")
    _splitting = config.get("kenzer", "splitting")
    _sync = config.get("kenzer", "syncing")
    _kenzerdb = config.get("kenzerdb", "path")
    _github = config.get("kenzerdb", "token")
    _repo = config.get("kenzerdb", "repo")
    _user = config.get("kenzerdb", "user")
    _home = config.get("env", "home")
    _greynoise = config.get("env", "greynoise")
    os.chdir(_kenzer)
    os.environ["HOME"] = _home
    if(os.path.exists(_kenzerdb) == False):
        os.system("mkdir "+_kenzerdb)
except:
    sys.exit(RED+"[!] invalid configurations"+CLEAR)

# kenzer


class Kenzer(object):

    # initializations
    def __init__(self):
        print(BLUE+"KENZER[3.38] by ARPSyndicate"+CLEAR)
        print(YELLOW+"automated web assets enumeration & scanning"+CLEAR)
        self.client = zulip.Client(email=_BotMail, site=_Site, api_key=_APIKey)
        self.upload = False
        if _subscribe == "True":
            self.subscribe()
            print(YELLOW+"[*] subscribed all streams"+CLEAR)
        if _uploads == "True":
            self.upload = True
            print(YELLOW+"[*] enabled uploads"+CLEAR)
        print(YELLOW+"[*] training chatterbot"+CLEAR)
        self.chatbot = ChatBot("Kenzer")
        self.trainer = ChatterBotCorpusTrainer(self.chatbot)
        time.sleep(1)
        self.trainer.train("chatterbot.corpus.english")
        time.sleep(1)
        self.modules = ["monitor", "program", "blacklist", "whitelist", "subenum", "repenum", "repoenum", "webenum", "servenum", "urlheadenum", "headenum", "socenum", "conenum", "dnsenum", "portenum", "asnenum", "urlenum", "favscan",
                        "cscan", "idscan", "subscan", "cvescan", "vulnscan", "reposcan", "portscan", "shodscan", "endscan", "buckscan", "vizscan", "enum", "scan", "recon", "hunt", "sync", "freaker"]
        print(YELLOW+"[*] KENZER is online"+CLEAR)
        print(
            YELLOW+"[*] {0} modules up & running".format(len(self.modules))+CLEAR)

    # subscribes to all streams
    def subscribe(self):
        try:
            json = self.client.get_streams()["streams"]
            streams = [{"name": stream["name"]} for stream in json]
            self.client.add_subscriptions(streams)
        except:
            print(RED+"[!] an exception occurred.... retrying...."+CLEAR)
            self.subscribe()

    # manual
    def man(self):
        message = "**KENZER[3.38]**\n"
        message += "**KENZER modules**\n"
        message += "`blacklist <target>,<regex>` - initializes & removes blacklisted targets\n"
        message += "`whitelist <target>,<regex>` - initializes & keeps only whitelisted targets\n"
        message += "`program <target>,<link>` - initializes the program to which target belongs\n"
        message += "`subenum[-<mode>[active/passive]] <target>` - enumerates subdomains\n"
        message += "`repenum <target>` - enumerates reputation of subdomains\n"
        message += "`repoenum <target>` - enumerates github repositories\n"
        message += "`portenum[-<mode>[100/1000/full/fast]] <target>` - enumerates open ports\n"
        message += "`servenum <target>` - enumerates services\n"
        message += "`webenum <target>` - enumerates webservers\n"
        message += "`headenum <target>` - enumerates additional info from webservers\n"
        message += "`urlheadenum <target>` - enumerates additional info from urls\n"
        message += "`asnenum <target>` - enumerates asn records\n"
        message += "`dnsenum <target>` - enumerates dns records\n"
        message += "`conenum <target>` - enumerates hidden files & directories\n"
        message += "`urlenum[-<mode>[active/passive]] <target>` - enumerates urls\n"
        message += "`socenum <target>` - enumerates social media accounts\n"
        message += "`subscan <target>` - hunts for subdomain takeovers\n"
        message += "`reposcan <target>` - scans github repositories for api key leaks\n"
        message += "`cscan[-<severity>[critical/high/medium/low/info]] <target>` - scan with customized templates\n"
        message += "`cvescan[-<severity>[critical/high/medium/low/info]] <target>` - hunts for CVEs\n"
        message += "`vulnscan[-<severity>[critical/high/medium/low/info]] <target>` - hunts for other common vulnerabilites\n"
        message += "`endscan[-<severity>[critical/high/medium/low/info]] <target>` - hunts for vulnerablities in custom endpoints\n"
        message += "`idscan[-<severity>[critical/high/medium/low/info]] <target>` - identifies applications running on webservers\n"
        message += "`portscan <target>` - scans open ports (nmap)(slow)\n"
        message += "`shodscan <target>` - scans open ports (shodan)(fast)\n"
        message += "`buckscan <target>` - hunts for unreferenced aws s3 buckets\n"
        message += "`favscan <target>` - fingerprints webservers using favicon\n"
        message += "`vizscan <target>` - screenshots applications running on webservers\n"
        message += "`enum <target>` - runs all enumerator modules\n"
        message += "`scan <target>` - runs all scanner modules\n"
        message += "`recon <target>` - runs all modules\n"
        message += "`hunt <target>` - runs your custom workflow\n"
        message += "`upload` - switches upload functionality\n"
        message += "`upgrade` - upgrades kenzer to latest version\n"
        message += "`monitor` - monitors ct logs for new subdomains\n"
        message += "`monitor normalize` - normalizes the enumerations from ct logs\n"
        message += "`monitor db` - monitors ct logs for domains in summary/domain.txt\n"
        message += "`monitor autohunt <frequency(default=5)>` - starts automated hunt while monitoring\n"
        message += "`sync` - synchronizes the local kenzerdb with github\n"
        message += "`freaker <module> [<target>]` - runs freaker module\n"
        message += "`kenzer <module>` - runs a specific module\n"
        message += "`kenzer man` - shows this manual\n"
        message += "multiple commands must be separated by comma(,)\n"
        message += "or you can just interact with chatterbot\n"
        self.sendMessage(message)
        return

    # sends messages
    def sendMessage(self, message):
        time.sleep(1)
        if self.type == "private":
            self.client.send_message({
                "type": self.type,
                "to": self.sender_email,
                "content": message
            })
        else:
            self.client.send_message({
                "type": self.type,
                "subject": self.subject,
                "to": self.display_recipient,
                "content": message
            })
        time.sleep(1)
        return

    # uploads output
    def uploader(self, domain, raw):
        global _kenzerdb
        global _Site
        org = domain
        data = _kenzerdb+org+"/"+raw
        if(os.path.exists(data) == False):
            return
        with open(data, 'rb') as fp:
            uploaded = self.client.call_endpoint(
                'user_uploads',
                method='POST',
                files=[fp],
            )
        self.sendMessage("{0}/{1} : {3}{2}".format(org,
                                                   raw, uploaded['uri'], _Site))
        return

    # removes log files
    def remlog(self):
        os.system("rm {0}*/*.log*".format(_kenzerdb))
        os.system("rm {0}*/*.old*".format(_kenzerdb))
        os.system(
            "rm -r {0}*/nuclei {0}*/jaeles {0}*/passive-jaeles {0}*/nxscan {0}*/gocrawler {0}*/reposcan {0}*/aquatone".format(_kenzerdb))
        os.system("find {0} -type f -empty -delete".format(_kenzerdb))
        return

    # splits .kenz files
    def splitkenz(self, cont):
        dtype = False
        if validators.domain(cont.lower()) == True or cont.lower() == "monitor":
            dtype = True
        else:
            try:
                ipaddress.ip_network(cont.replace("#", "/"))
            except ValueError:
                return
        self.enum = enumerator.Enumerator(
            cont.lower(), _kenzerdb, _kenzer, dtype)
        self.enum.splitkenz()
        return

    # merges .kenz files
    def mergekenz(self, cont):
        dtype = False
        if validators.domain(cont.lower()) == True or cont.lower() == "monitor":
            dtype = True
        else:
            try:
                ipaddress.ip_network(cont.replace("#", "/"))
            except ValueError:
                return
        self.enum = enumerator.Enumerator(
            cont.lower(), _kenzerdb, _kenzer, dtype)
        self.enum.mergekenz()
        return

    # monitors ct logs
    def monitor(self):
        self.sendMessage("[monitor - running in background]")
        self.monitor = monitor.Monitor(_kenzerdb, " ".join(self.content[2:]))
        self.monitor.certex()
        return

    # monitors ct logs for domains in summary/domain.txt
    def monitor_kenzerdb(self):
        domfile = _kenzerdb+"../summary/domain.txt"
        with open(domfile) as f:
            line = len(f.readlines())
        self.sendMessage("[monitor - running in background]")
        self.monitor = monitor.Monitor(_kenzerdb)
        self.monitor.certex()
        return

    # starts automated hunt while monitoring
    def monitor_autohunt(self, freq=5):
        i = 1
        while i <= freq:
            self.monitor = monitor.Monitor(_kenzerdb)
            self.content = "**{0}** hunt monitor".format(
                _BotMail.split("@")[0]).split()
            self.hunt()
            self.monitor.normalize()
            self.sendMessage(
                "[autohunt - ({0}%)]".format(int(i/freq*100)))
            if _sync == "True":
                self.sync()
            i = i+1
        return

    # normalizes enumerations from ct logs
    def normalize(self):
        self.monitor = monitor.Monitor(_kenzerdb, " ".join(self.content[2:]))
        self.monitor.normalize()
        self.sendMessage("[normalized]")
        return

    # initializes the program to which target belongs
    def program(self):
        for i in range(2, len(self.content)):
            dtype = False
            domain = self.content[i].split(",")[0].lower()
            if validators.domain(domain) == True or domain == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(domain)
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        self.content[i].lower()))
                    continue
            self.sendMessage(
                "[program - ({0}%)] {1}".format(int((i-1)/(len(self.content)-2)*100), domain))
            self.enum = enumerator.Enumerator(
                domain, _kenzerdb, _kenzer, dtype)
            message = self.enum.program(
                self.content[i].split(",")[1])
            self.sendMessage(
                "[program - ({0}%) - {1}] {2}".format(int((i-1)/(len(self.content)-2)*100), message, domain))
            if self.upload:
                file = "program.kenz"
                self.uploader(self.content[i], file)
        return

    # initializes & removes blacklisted targets
    def blacklist(self):
        for i in range(2, len(self.content)):
            dtype = True
            domain = self.content[i].split(",")[0].lower()
            if(validators.domain(domain) != True):
                self.sendMessage("[invalid] {0}".format(
                    self.content[i].lower()))
                continue
            self.sendMessage(
                "[blacklist - ({0}%)] {1}".format(int((i-1)/(len(self.content)-2)*100), domain))
            self.enum = enumerator.Enumerator(
                domain, _kenzerdb, _kenzer, dtype)
            message = self.enum.blacklist(
                self.content[i].split(",")[1])
            self.sendMessage(
                "[blacklist - ({0}%) - {1}] {2}".format(int((i-1)/(len(self.content)-2)*100), message, domain))
            if self.upload:
                file = "blacklist.kenz"
                self.uploader(self.content[i], file)
        return

    # initializes & keeps only whitelisted targets
    def whitelist(self):
        for i in range(2, len(self.content)):
            dtype = True
            domain = self.content[i].split(",")[0].lower()
            if(validators.domain(domain) != True):
                self.sendMessage("[invalid] {0}".format(
                    self.content[i].lower()))
                continue
            self.sendMessage(
                "[whitelist - ({0}%)] {1}".format(int((i-1)/(len(self.content)-2)*100), domain))
            self.enum = enumerator.Enumerator(
                domain, _kenzerdb, _kenzer, dtype)
            message = self.enum.whitelist(
                self.content[i].split(",")[1])
            self.sendMessage(
                "[whitelist - ({0}%) - {1}] {2}".format(int((i-1)/(len(self.content)-2)*100), message, domain))
            if self.upload:
                file = "whitelist.kenz"
                self.uploader(self.content[i], file)
        return

    # enumerates subdomains
    def subenum(self, mode=""):
        for i in range(2, len(self.content)):
            dtype = True
            if validators.domain(self.content[i].lower()) != True and self.content[i].lower() != "monitor":
                self.sendMessage("[invalid] {0}".format(
                    self.content[i].lower()))
                continue
            display = ""
            if(len(mode) > 0):
                display = "({0})".format(mode)
            self.sendMessage(
                "[subenum{2} - ({0}%)] {1}".format(int((i-1)/(len(self.content)-2)*100), self.content[i].lower(),display))
            if self.content[i].lower() == "monitor":
                self.monitor = monitor.Monitor(_kenzerdb)
                self.monitor.initialize()
                message = self.monitor.subenum()
            else:
                self.enum = enumerator.Enumerator(
                    self.content[i].lower(), _kenzerdb, _kenzer, dtype)

                message = self.enum.subenum(_github, mode)
            self.sendMessage("[subenum{3} - ({0}%) - {1}] {2}".format(
                int((i-1)/(len(self.content)-2)*100), message, self.content[i].lower(), display))
            if self.upload:
                file = "subenum.kenz"
                self.uploader(self.content[i], file)
        return

    # probes services from enumerated ports
    def servenum(self):
        for i in range(2, len(self.content)):
            dtype = False
            if validators.domain(self.content[i].lower()) == True or self.content[i].lower() == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        self.content[i].lower()))
                    continue
            self.sendMessage(
                "[servenum - ({0}%)] {1}".format(int((i-1)/(len(self.content)-2)*100), self.content[i].lower()))
            self.enum = enumerator.Enumerator(
                self.content[i].lower(), _kenzerdb, _kenzer, dtype)
            message = self.enum.servenum()
            self.sendMessage("[servenum - ({0}%) - {1}] {2}".format(
                int((i-1)/(len(self.content)-2)*100), message, self.content[i].lower()))
            if self.upload:
                file = "servenum.kenz"
                self.uploader(self.content[i], file)
        return

    # probes web servers from enumerated ports
    def webenum(self):
        for i in range(2, len(self.content)):
            dtype = False
            if validators.domain(self.content[i].lower()) == True or self.content[i].lower() == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        self.content[i].lower()))
                    continue
            self.sendMessage(
                "[webenum - ({0}%)] {1}".format(int((i-1)/(len(self.content)-2)*100), self.content[i].lower()))
            self.enum = enumerator.Enumerator(
                self.content[i].lower(), _kenzerdb, _kenzer, dtype)
            message = self.enum.webenum()
            self.sendMessage("[webenum - ({0}%) - {1}] {2}".format(
                int((i-1)/(len(self.content)-2)*100), message, self.content[i].lower()))
            if self.upload:
                file = "webenum.kenz"
                self.uploader(self.content[i], file)
        return

    # enumerates additional info from webservers
    def headenum(self):
        for i in range(2, len(self.content)):
            dtype = False
            if validators.domain(self.content[i].lower()) == True or self.content[i].lower() == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        self.content[i].lower()))
                    continue
            self.sendMessage(
                "[headenum - ({0}%)] {1}".format(int((i-1)/(len(self.content)-2)*100), self.content[i].lower()))
            self.enum = enumerator.Enumerator(
                self.content[i].lower(), _kenzerdb, _kenzer, dtype)
            message = self.enum.headenum()
            self.sendMessage("[headenum - ({0}%) - {1}] {2}".format(
                int((i-1)/(len(self.content)-2)*100), message, self.content[i].lower()))
            if self.upload:
                file = "headenum.kenz"
                self.uploader(self.content[i], file)
        return

    # enumerates additional info from urls
    def urlheadenum(self):
        for i in range(2, len(self.content)):
            dtype = True
            if(validators.domain(self.content[i].lower()) != True):
                self.sendMessage("[invalid] {0}".format(
                    self.content[i].lower()))
                continue
            self.sendMessage("[urlheadenum - ({0}%)] {1}".format(
                int((i-1)/(len(self.content)-2)*100), self.content[i].lower()))
            self.enum = enumerator.Enumerator(
                self.content[i].lower(), _kenzerdb, _kenzer, dtype)
            message = self.enum.urlheadenum()
            self.sendMessage("[urlheadenum - ({0}%) - {1}] {2}".format(
                int((i-1)/(len(self.content)-2)*100), message, self.content[i].lower()))
            if self.upload:
                file = "urlheadenum.kenz"
                self.uploader(self.content[i], file)
        return

    # enumerates dns records
    def dnsenum(self):
        for i in range(2, len(self.content)):
            dtype = True
            if(validators.domain(self.content[i].lower()) != True and self.content[i].lower() != "monitor"):
                self.sendMessage("[invalid] {0}".format(
                    self.content[i].lower()))
                continue
            self.sendMessage(
                "[dnsenum - ({0}%)] {1}".format(int((i-1)/(len(self.content)-2)*100), self.content[i].lower()))
            self.enum = enumerator.Enumerator(
                self.content[i].lower(), _kenzerdb, _kenzer, dtype)
            message = self.enum.dnsenum()
            self.sendMessage("[dnsenum - ({0}%) - {1}] {2}".format(
                int((i-1)/(len(self.content)-2)*100), message, self.content[i].lower()))
            if self.upload:
                file = "dnsenum.kenz"
                self.uploader(self.content[i], file)
        return

    # enumerates hidden files & directories
    def conenum(self):
        for i in range(2, len(self.content)):
            dtype = True
            if(validators.domain(self.content[i].lower()) != True and self.content[i].lower() != "monitor"):
                self.sendMessage("[invalid] {0}".format(
                    self.content[i].lower()))
                continue
            self.sendMessage(
                "[conenum - ({0}%)] {1}".format(int((i-1)/(len(self.content)-2)*100), self.content[i].lower()))
            self.enum = enumerator.Enumerator(
                self.content[i].lower(), _kenzerdb, _kenzer, dtype)
            message = self.enum.conenum()
            self.sendMessage(
                "[conenum - ({0}%) - {1}] {2}".format(int((i-1)/(len(self.content)-2)*100), message, self.content[i].lower()))
            if self.upload:
                file = "conenum.kenz"
                self.uploader(self.content[i], file)
        return

    # enumerates asn for enumerated subdomains
    def asnenum(self):
        for i in range(2, len(self.content)):
            dtype = True
            if(validators.domain(self.content[i].lower()) != True and self.content[i].lower() != "monitor"):
                self.sendMessage("[invalid] {0}".format(
                    self.content[i].lower()))
                continue
            self.sendMessage(
                "[asnenum - ({0}%)] {1}".format(int((i-1)/(len(self.content)-2)*100), self.content[i].lower()))
            self.enum = enumerator.Enumerator(
                self.content[i].lower(), _kenzerdb, _kenzer, dtype)
            message = self.enum.asnenum()
            self.sendMessage("[asnenum - ({0}%) - {1}] {2}".format(
                int((i-1)/(len(self.content)-2)*100), message, self.content[i].lower()))
            if self.upload:
                file = "asnenum.kenz"
                self.uploader(self.content[i], file)
        return

    # enumerates open ports
    def portenum(self, mode=""):
        for i in range(2, len(self.content)):
            dtype = False
            if validators.domain(self.content[i].lower()) == True or self.content[i].lower() == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        self.content[i].lower()))
                    continue
            display = ""
            if(len(mode) > 0):
                display = "({0})".format(mode)
            self.sendMessage(
                "[portenum{2} - ({0}%)] {1}".format(int((i-1)/(len(self.content)-2)*100), self.content[i].lower(), display))
            self.enum = enumerator.Enumerator(
                self.content[i].lower(), _kenzerdb, _kenzer, dtype)
            message = self.enum.portenum(mode)
            self.sendMessage("[portenum{3} - ({0}%) - {1}] {2}".format(
                int((i-1)/(len(self.content)-2)*100), message, self.content[i].lower(), display))
            if self.upload:
                file = "portenum.kenz"
                self.uploader(self.content[i], file)
        return

    # enumerates reputation of subdomains
    def repenum(self):
        for i in range(2, len(self.content)):
            dtype = False
            if validators.domain(self.content[i].lower()) == True or self.content[i].lower() == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        self.content[i].lower()))
                    continue
            self.sendMessage(
                "[repenum - ({0}%)] {1}".format(int((i-1)/(len(self.content)-2)*100), self.content[i].lower()))
            self.enum = enumerator.Enumerator(
                self.content[i].lower(), _kenzerdb, _kenzer, dtype)
            message = self.enum.repenum(_greynoise)
            self.sendMessage("[repenum - ({0}%) - {1}] {2}".format(
                int((i-1)/(len(self.content)-2)*100), message, self.content[i].lower()))
            if self.upload:
                file = "repenum.kenz"
                self.uploader(self.content[i], file)
        return

    # enumerates github repositories
    def repoenum(self):
        for i in range(2, len(self.content)):
            dtype = True
            if(validators.domain(self.content[i].lower()) != True):
                self.sendMessage("[invalid] {0}".format(
                    self.content[i].lower()))
                continue
            self.sendMessage(
                "[repoenum - ({0}%)] {1}".format(int((i-1)/(len(self.content)-2)*100), self.content[i].lower()))
            self.enum = enumerator.Enumerator(
                self.content[i].lower(), _kenzerdb, _kenzer, dtype)
            message = self.enum.repoenum(_github)
            self.sendMessage("[repoenum - ({0}%) - {1}] {2}".format(
                int((i-1)/(len(self.content)-2)*100), message, self.content[i].lower()))
            if self.upload:
                file = "repoenum.kenz"
                self.uploader(self.content[i], file)
        return


    # enumerates urls
    def urlenum(self, mode=""):
        for i in range(2, len(self.content)):
            dtype = True
            if(validators.domain(self.content[i].lower()) != True):
                self.sendMessage("[invalid] {0}".format(
                    self.content[i].lower()))
                continue
            display = ""
            if(len(mode) > 0):
                display = "({0})".format(mode)
            self.sendMessage(
                "[urlenum{2} - ({0}%)] {1}".format(int((i-1)/(len(self.content)-2)*100), self.content[i].lower(),display))
            self.enum = enumerator.Enumerator(
                self.content[i].lower(), _kenzerdb, _kenzer, dtype)
            message = self.enum.urlenum(_github, mode)
            self.sendMessage("[urlenum{3} - ({0}%) - {1}] {2}".format(
                int((i-1)/(len(self.content)-2)*100), message, self.content[i].lower(),display))
            if self.upload:
                file = "urlenum.kenz"
                self.uploader(self.content[i], file)
        return

    # hunts for subdomain takeovers
    def subscan(self):
        for i in range(2, len(self.content)):
            dtype = False
            if validators.domain(self.content[i].lower()) == True or self.content[i].lower() == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        self.content[i].lower()))
                    continue
            self.sendMessage(
                "[subscan - ({0}%)] {1}".format(int((i-1)/(len(self.content)-2)*100), self.content[i].lower()))
            self.scan = scanner.Scanner(
                self.content[i].lower(), _kenzerdb, dtype, _kenzer)
            message = self.scan.subscan()
            self.sendMessage("[subscan - ({0}%) - {1}] {2}".format(
                int((i-1)/(len(self.content)-2)*100), message, self.content[i].lower()))
            if self.upload:
                file = "subscan.kenz"
                self.uploader(self.content[i], file)
        return

    # enumerates social media accounts
    def socenum(self):
        for i in range(2, len(self.content)):
            dtype = False
            if validators.domain(self.content[i].lower()) == True:
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        self.content[i].lower()))
                    continue
            self.sendMessage(
                "[socenum - ({0}%)] {1}".format(int((i-1)/(len(self.content)-2)*100), self.content[i].lower()))
            self.enum = enumerator.Enumerator(
                self.content[i].lower(), _kenzerdb, _kenzer, dtype)
            message = self.enum.socenum()
            self.sendMessage("[socenum - ({0}%) - {1}] {2}".format(
                int((i-1)/(len(self.content)-2)*100), message, self.content[i].lower()))
            if self.upload:
                file = "socenum.kenz"
                self.uploader(self.content[i], file)
        return

    # scans with customized templates
    def cscan(self, severity=""):
        for i in range(2, len(self.content)):
            dtype = False
            if validators.domain(self.content[i].lower()) == True or self.content[i].lower() == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        self.content[i].lower()))
                    continue
            display = ""
            if(len(severity) > 0):
                display = "({0})".format(severity)
            self.sendMessage("[cscan{2} - ({0}%)] {1}".format(
                int((i-1)/(len(self.content)-2)*100), self.content[i].lower(), display))
            self.scan = scanner.Scanner(
                self.content[i].lower(), _kenzerdb, dtype, _kenzer, severity)
            message = self.scan.cscan()
            self.sendMessage("[cscan{3} - ({0}%) - {1}] {2}".format(
                int((i-1)/(len(self.content)-2)*100), message, self.content[i].lower(), display))
            if self.upload:
                file = "cscan.kenz"
                self.uploader(self.content[i], file)
        return

    # hunts for CVEs
    def cvescan(self, severity=""):
        for i in range(2, len(self.content)):
            dtype = False
            if validators.domain(self.content[i].lower()) == True or self.content[i].lower() == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        self.content[i].lower()))
                    continue
            display = ""
            if(len(severity) > 0):
                display = "({0})".format(severity)
            self.sendMessage("[cvescan{2} - ({0}%)] {1}".format(
                int((i-1)/(len(self.content)-2)*100), self.content[i].lower(), display))
            self.scan = scanner.Scanner(
                self.content[i].lower(), _kenzerdb, dtype, _kenzer, severity)
            message = self.scan.cvescan()
            self.sendMessage("[cvescan{3} - ({0}%) - {1}] {2}".format(
                int((i-1)/(len(self.content)-2)*100), message, self.content[i].lower(), display))
            if self.upload:
                file = "cvescan.kenz"
                self.uploader(self.content[i], file)
        return

    # hunts for other common vulnerabilities
    def vulnscan(self, severity=""):
        for i in range(2, len(self.content)):
            dtype = False
            if validators.domain(self.content[i].lower()) == True or self.content[i].lower() == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        self.content[i].lower()))
                    continue
            display = ""
            if(len(severity) > 0):
                display = "({0})".format(severity)
            self.sendMessage("[vulnscan{2} - ({0}%)] {1}".format(
                int((i-1)/(len(self.content)-2)*100), self.content[i].lower(), display))
            self.scan = scanner.Scanner(
                self.content[i].lower(), _kenzerdb, dtype, _kenzer, severity)
            message = self.scan.vulnscan()
            self.sendMessage("[vulnscan{3} - ({0}%) - {1}] {2}".format(
                int((i-1)/(len(self.content)-2)*100), message, self.content[i].lower(), display))
            if self.upload:
                file = "vulnscan.kenz"
                self.uploader(self.content[i], file)
        return

    # scans open ports (shodan)(fast)
    def shodscan(self):
        for i in range(2, len(self.content)):
            dtype = False
            if validators.domain(self.content[i].lower()) == True or self.content[i].lower() == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        self.content[i].lower()))
                    continue
            self.sendMessage(
                "[shodscan - ({0}%)] {1}".format(int((i-1)/(len(self.content)-2)*100), self.content[i].lower()))
            self.scan = scanner.Scanner(
                self.content[i].lower(), _kenzerdb, dtype, _kenzer)
            message = self.scan.shodscan()
            self.sendMessage(
                "[shodscan - ({0}%) {2}] {1}".format(int((i-1)/(len(self.content)-2)*100), self.content[i].lower(), message))
            if self.upload:
                file = "shodscan.kenz"
                self.uploader(self.content[i], file)
        return
        
    # scans open ports (nmap)(slow)
    def portscan(self):
        for i in range(2, len(self.content)):
            dtype = False
            if validators.domain(self.content[i].lower()) == True:
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        self.content[i].lower()))
                    continue
            self.sendMessage(
                "[portscan - ({0}%)] {1}".format(int((i-1)/(len(self.content)-2)*100), self.content[i].lower()))
            self.scan = scanner.Scanner(
                self.content[i].lower(), _kenzerdb, dtype, _kenzer)
            message = self.scan.portscan()
            self.sendMessage(
                "[portscan - ({0}%) {2}] {1}".format(int((i-1)/(len(self.content)-2)*100), self.content[i].lower(), message))
            if self.upload:
                file = "portscan.kenz"
                self.uploader(self.content[i], file)
        return

    # scans github repositories for api key leaks
    def reposcan(self):
        for i in range(2, len(self.content)):
            dtype = True
            if(validators.domain(self.content[i].lower()) != True):
                self.sendMessage("[invalid] {0}".format(
                    self.content[i].lower()))
                continue
            display = ""
            self.sendMessage("[reposcan - ({0}%)] {1}".format(
                int((i-1)/(len(self.content)-2)*100), self.content[i].lower()))
            self.scan = scanner.Scanner(
                self.content[i].lower(), _kenzerdb, dtype, _kenzer)
            message = self.scan.reposcan()
            self.sendMessage("[reposcan - ({0}%) - {1}] {2}".format(
                int((i-1)/(len(self.content)-2)*100), message, self.content[i].lower()))
            if self.upload:
                file = "reposcan.kenz"
                self.uploader(self.content[i], file)
        return

    # hunts for vulnerablities in custom endpoints
    def endscan(self, severity=""):
        for i in range(2, len(self.content)):
            dtype = False
            if validators.domain(self.content[i].lower()) == True:
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        self.content[i].lower()))
                    continue
            display = ""
            if(len(severity) > 0):
                display = "({0})".format(severity)
            self.sendMessage("[endscan{2} - ({0}%)] {1}".format(
                int((i-1)/(len(self.content)-2)*100), self.content[i].lower(), display))
            self.scan = scanner.Scanner(
                self.content[i].lower(), _kenzerdb, dtype, _kenzer, severity)
            message = self.scan.endscan()
            self.sendMessage("[endscan{3} - ({0}%) - {1}] {2}".format(
                int((i-1)/(len(self.content)-2)*100), message, self.content[i].lower(), display))
            if self.upload:
                file = "endscan.kenz"
                self.uploader(self.content[i], file)
        return

    # hunts for subdomain takeovers
    def buckscan(self):
        for i in range(2, len(self.content)):
            dtype = False
            if validators.domain(self.content[i].lower()) == True or self.content[i].lower() == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        self.content[i].lower()))
                    continue
            self.sendMessage(
                "[buckscan - ({0}%)] {1}".format(int((i-1)/(len(self.content)-2)*100), self.content[i].lower()))
            self.scan = scanner.Scanner(
                self.content[i].lower(), _kenzerdb, dtype, _kenzer)
            message = self.scan.buckscan()
            self.sendMessage("[buckscan - ({0}%) - {1}] {2}".format(
                int((i-1)/(len(self.content)-2)*100), message, self.content[i].lower()))
            if self.upload:
                file = "buckscan.kenz"
                self.uploader(self.content[i], file)
        return

    # fingerprints servers using favicons
    def favscan(self):
        for i in range(2, len(self.content)):
            dtype = False
            if validators.domain(self.content[i].lower()) == True or self.content[i].lower() == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        self.content[i].lower()))
                    continue
            self.sendMessage(
                "[favscan - ({0}%)] {1}".format(int((i-1)/(len(self.content)-2)*100), self.content[i].lower()))
            self.scan = scanner.Scanner(
                self.content[i].lower(), _kenzerdb, dtype, _kenzer)
            message = self.scan.favscan()
            self.sendMessage("[favscan - ({0}%) - {1}] {2}".format(
                int((i-1)/(len(self.content)-2)*100), message, self.content[i].lower()))
            if self.upload:
                file = "favscan.kenz"
                self.uploader(self.content[i], file)
        return

    # identifies applications running on webservers
    def idscan(self, severity=""):
        for i in range(2, len(self.content)):
            dtype = False
            if validators.domain(self.content[i].lower()) == True or self.content[i].lower() == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        self.content[i].lower()))
                    continue
            display = ""
            if(len(severity) > 0):
                display = "({0})".format(severity)
            self.sendMessage("[idscan{2} - ({0}%)] {1}".format(
                int((i-1)/(len(self.content)-2)*100), self.content[i].lower(), display))
            self.scan = scanner.Scanner(
                self.content[i].lower(), _kenzerdb, dtype, _kenzer, severity)
            message = self.scan.idscan()
            self.sendMessage("[idscan{3} - ({0}%) - {1}] {2}".format(
                int((i-1)/(len(self.content)-2)*100), message, self.content[i].lower(), display))
            if self.upload:
                file = "idscan.kenz"
                self.uploader(self.content[i], file)
        return

    # screenshots applications running on webservers
    def vizscan(self):
        for i in range(2, len(self.content)):
            dtype = False
            if validators.domain(self.content[i].lower()) == True or self.content[i].lower() == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        self.content[i].lower()))
                    continue
            self.sendMessage(
                "[vizscan - ({0}%)] {1}".format(int((i-1)/(len(self.content)-2)*100), self.content[i].lower()))
            self.scan = scanner.Scanner(
                self.content[i].lower(), _kenzerdb, dtype, _kenzer)
            message = self.scan.vizscan()
            self.sendMessage(
                "[vizscan - ({0}%) - {2}] {1}".format(int((i-1)/(len(self.content)-2)*100), self.content[i].lower(), message))
            if self.upload:
                file = "vizscan.kenz"
                self.uploader(self.content[i], file)
        return

    # runs all enumeration modules
    def enumall(self):
        self.subenum()
        self.repoenum()
        self.asnenum()
        self.portenum()
        self.servenum()
        self.webenum()
        self.headenum()
        self.dnsenum()
        self.socenum()
        self.conenum()
        # experimental ones
        # self.repenum()
        # self.urlenum()
        # self.urlheadenum()
        return

    # runs all scanning modules
    def scanall(self):
        self.shodscan()
        self.favscan()
        self.idscan()
        self.subscan()
        self.buckscan()
        self.cvescan()
        self.vulnscan()
        self.reposcan()
        self.vizscan()
        self.portscan()
        # experimental ones
        # self.endscan()
        return

    # define your custom workflow - used while autohunt
    def hunt(self):
        self.subenum()
        self.asnenum()
        self.portenum()
        self.servenum()
        self.webenum()
        self.headenum()
        self.dnsenum()
        self.subscan()
        self.shodscan()
        self.idscan()
        self.favscan()
        self.buckscan()
        self.cvescan("critical")
        self.cvescan("high")
        self.cvescan("medium")
        self.cvescan("low")
        self.vulnscan("critical")
        self.vulnscan("high")
        self.vulnscan("medium")
        self.vulnscan("low")
        self.vizscan()
        # experimental ones
        #self.freaker("wapiti-scan", "monitor")
        # self.repoenum()
        # self.conenum()
        # self.repenum()
        # self.socenum()
        # self.portscan()
        # self.vizscan()
        # self.urlenum()
        # self.reposcan()
        # self.urlheadenum()
        # self.endscan()
        return

    # runs all modules
    def recon(self):
        self.enumall()
        self.scanall()
        return
    
    # runs freaker module
    def freaker(self, exploit, target):
        self.sendMessage("[freaker][{1}] {0}".format(target, exploit))
        os.system("freaker -c {0} -r {1} -t {2}".format("configs/freaker.yaml", exploit, target))
        return

    # synchronizes the local kenzerdb with github
    def sync(self):
        if _logging == "False":
                self.remlog()
        for tar in os.listdir(_kenzerdb):
            if _splitting == "True":
                self.splitkenz(tar.lower())
        os.system("rm {0}../.git/index.lock".format(_kenzerdb))
        os.system("cd {0} && git remote set-url origin https://{1}@github.com/{2}/{3}.git && git pull && cd ../scripts && bash generate.sh && cd .. && git add . && git commit -m \"{4}`date`)\" && git push".format(
            _kenzerdb, _github, _user, _repo, _BotMail+"("))
        for tar in os.listdir(_kenzerdb):
                self.mergekenz(tar.lower())
        self.sendMessage("[synced]")
        return

    # upgrades kenzer to latest version
    def upgrade(self):
        os.system("bash update.sh")
        self.sendMessage("[upgraded]")
        return

    # controls
    def process(self, text):
        self.content = text["content"].split()
        self.sender_email = text["sender_email"]
        self.type = text["type"]
        self.display_recipient = text['display_recipient']
        self.subject = text['subject']
        content = self.content
        print(content)
        if self.sender_email == _BotMail:
            return
        try:
            if len(content) > 1 and content[0].lower() == "@**{0}**".format(_BotMail.split('@')[0].replace("-bot", "")):
                for comd in content[1].split(","):
                    if comd.lower() == "man":
                        if len(content) == 2:
                            self.man()
                        else:
                            message = "excuse me???"
                            self.sendMessage(message)
                    elif comd.lower() == "monitor":
                        if content[2].lower() == "normalize":
                            self.normalize()
                        elif content[2].lower() == "db":
                            self.monitor_kenzerdb()
                        elif content[2].lower() == "autohunt":
                            if len(content) == 4:
                                self.monitor_autohunt(int(content[3]))
                            else:
                                self.monitor_autohunt()
                        else:
                            self.monitor()
                    elif comd.lower() == "blacklist":
                        self.blacklist()
                    elif comd.lower() == "whitelist":
                        self.whitelist()
                    elif comd.lower() == "program":
                        self.program()
                    elif comd.split("-")[0].lower() == "subenum":
                        if len(comd.split("-")) > 1:
                            self.subenum(comd.split("-")[1].lower())
                        else:
                            self.subenum()
                    elif comd.lower() == "repenum":
                        self.repenum()
                    elif comd.lower() == "repoenum":
                        self.repoenum()
                    elif comd.lower() == "webenum":
                        self.webenum()
                    elif comd.lower() == "servenum":
                        self.servenum()
                    elif comd.lower() == "socenum":
                        self.socenum()
                    elif comd.lower() == "headenum":
                        self.headenum()
                    elif comd.lower() == "urlheadenum":
                        self.urlheadenum()
                    elif comd.lower() == "asnenum":
                        self.asnenum()
                    elif comd.lower() == "dnsenum":
                        self.dnsenum()
                    elif comd.lower() == "conenum":
                        self.conenum()
                    elif comd.lower() == "favscan":
                        self.favscan()
                    elif comd.split("-")[0].lower() == "portenum":
                        if len(comd.split("-")) > 1:
                            self.portenum(comd.split("-")[1].lower())
                        else:
                            self.portenum()
                    elif comd.split("-")[0].lower() == "urlenum":
                        if len(comd.split("-")) > 1:
                            self.urlenum(comd.split("-")[1].lower())
                        else:
                            self.urlenum()
                    elif comd.lower() == "subscan":
                        self.subscan()
                    elif comd.split("-")[0].lower() == "cscan":
                        if len(comd.split("-")) > 1:
                            for sev in range(1,len(comd.split("-"))):
                                self.cscan(comd.split("-")[sev].lower())
                        else:
                            self.cscan()
                    elif comd.split("-")[0].lower() == "cvescan":
                        if len(comd.split("-")) > 1:
                            for sev in range(1,len(comd.split("-"))):
                                self.cvescan(comd.split("-")[sev].lower())
                        else:
                            self.cvescan()
                    elif comd.split("-")[0].lower() == "vulnscan":
                        if len(comd.split("-")) > 1:
                            for sev in range(1,len(comd.split("-"))):
                                self.vulnscan(comd.split("-")[sev].lower())
                        else:
                            self.vulnscan()
                    elif comd.lower() == "portscan":
                        self.portscan()
                    elif comd.lower() == "shodscan":
                        self.shodscan()
                    elif comd.lower() == "reposcan":
                        self.reposcan()
                    elif comd.split("-")[0].lower() == "endscan":
                        if len(comd.split("-")) > 1:
                            for sev in range(1,len(comd.split("-"))):
                                self.endscan(comd.split("-")[sev].lower())
                        else:
                            self.endscan()
                    elif comd.split("-")[0].lower() == "idscan":
                        if len(comd.split("-")) > 1:
                            for sev in range(1,len(comd.split("-"))):
                                self.idscan(comd.split("-")[sev].lower())
                        else:
                            self.idscan()
                    elif comd.lower() == "vizscan":
                        self.vizscan()
                    elif comd.lower() == "buckscan":
                        self.buckscan()
                    elif comd.lower() == "enum":
                        self.enumall()
                    elif comd.lower() == "scan":
                        self.scanall()
                    elif comd.lower() == "hunt":
                        self.hunt()
                    elif comd.lower() == "recon":
                        self.recon()
                    elif comd.lower() == "sync":
                        self.sync()
                    elif comd.lower() == "freaker":
                        if len(content) >= 4:
                            for i in range(3, len(content)):
                                self.freaker(content[2].lower(), content[i].lower())
                        else:
                            self.freaker(content[2].lower(), "*")
                    elif comd.lower() == "upgrade":
                        self.upgrade()
                    elif comd.lower() == "upload":
                        self.upload = not self.upload
                        self.sendMessage("upload: "+str(self.upload))
                    else:
                        message = self.chatbot.get_response(' '.join(self.content))
                        message = message.serialize()['text']
                        self.sendMessage(message)
        except Exception as exception:
            self.sendMessage("[exception] {0}:{1}".format(
                type(exception).__name__, str(exception)))
            print(exception.__class__.__name__ + ": " + str(exception))
        return

# main


def main():
    bot = Kenzer()
    bot.client.call_on_each_message(bot.process)


# runs main
if __name__ == "__main__":
    main()
