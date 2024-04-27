from termcolor import colored
import subprocess
import sys

from netscan import portscan
from exploits import *

class Vulnscanner:
    def __init__(self, *,
                 hostIP=None,
                 hostPort=None,
                 hostPortRange=None,
                 subdomains=None,
                 directories=None) -> None:

        self.hostIP = str(hostIP)
        self.hostPort = int(hostPort)
        self.hostPortRange = int(hostPortRange)
        self.subdomains: str = str(subdomains)
        self.directories: str = str(directories)


    def scan(self, *, exploit=False):
        #SCANS FOR VULNERABILITIES ON SERVICES
        print(colored(f"[+] Scanning host ({self.hostIP}).", "green"))
        
        for port in range(self.hostPort, self.hostPortRange + 1):
            hostscan: PortScanner = portscan.PortScanner(hostIP=self.hostIP, hostPort=port)
            flag: PortScanner = hostscan.send_tcp_packet(verbose=0)

            if flag == 'SA':
                #EACH WILL HAVE THEIR OWN FUNCTION AND PACKAGE TO PERFORM

                if port == 21: #FTP
                    print(colored(f"[!] {hostscan.get_port_service()} detected on host {self.hostIP} port {port}", "yellow"))
                    if bool(exploit) == True:
                        print(colored("[+] Performing actions..", "green"))
                        try:
                            pass
                        except Exception as error:
                            print(colored(f"[-] {error}", "red"))
                        
                elif port == 80 or port == 443: #HTTP/HTTPS
                    print(colored(f"[!] {hostscan.get_port_service()} detected on host {self.hostIP} port {port}", "yellow"))
                    if bool(exploit) == True:
                        print(colored("[+] Performing actions..", "green"))
                        try:
                            fuzzer.Fuzzer(url=self.hostIP,
                                               subdomains=self.subdomains,
                                               directories=self.directories
                                               ).fuzz()
                        except Exception as error:
                            print(colored(f"[-] {error}", "red"))
        
        
    def execute_command(self, command):
        #COMMAND EXECUTIONS
        if command[0] == 'options':
            print("")
            print(f'| Subdomains Path (set subdomain)\n└─> {colored(self.subdomains, "green")}')
            print(f'| Directories Path (set directories)\n└─> {colored(self.directories, "green")}')
            print(f'| Host IP (set ip)\n└─> {colored(self.hostIP, "green")}')
            print(f'| Host Port (set port/set portrange)\n└─> {colored(self.hostPort, "green")} - {colored(self.hostPortRange, "green")}')

        elif command[0] == 'portscan':
            try:
                portscan.PortScanner(hostIP=self.hostIP, hostPort=self.hostPort, hostRangePort=self.hostPortRange).scan_ports()
            except Exception as error:
                print(colored(f"[-] {error}", "red"))

        elif command[0] == 'fuzz':
            try:
                fuzzer.Fuzzer(url=self.hostIP,
                              subdomains=self.subdomains,
                              directories=self.directories
                              ).fuzz()
            except Exception as error:
                print(colored(f"[-] {error}", "red"))

        elif command[0] == 'scan':
            try:
                self.scan(exploit=True)
            except Exception as error:
                print(colored(f"[-] {error}", "red"))

        elif command[0] == 'clear':
            subprocess.Popen('clear')
            
        #COMMAND SET VALUES
        elif command[0] == 'set' and command[1] == 'ip':
            self.hostIP = str(command[2])
            print(colored(f"[+] host ip has been set to {self.hostIP}", "green"))

        elif command[0] == 'set' and command[1] == 'port':
            self.hostPort = int(command[2])
            print(colored(f"[+] host port has been set to {self.hostPort}", "green"))

        elif command[0] == 'set' and command[1] == 'subdomain':
            self.subdomains = str(command[2])
            print(colored(f"[+] Subdomains has been set to {self.subdomains}", "green"))

        elif command[0] == 'set' and command[1] == 'directories':
            self.directories = str(command[2])
            print(colored(f"[+] Directories has been set to {self.directories}", "green"))

        elif command[0] == 'set' and command[1] == 'portrange':
            self.hostPortRange = int(command[2])
            print(colored(f"[+] host port range has been set to {self.hostPortRange}", "green"))

        else:
            print(colored("[-] No such command..", "red"))


    def console(self):
        while True:
            command = input('\n┌── Console\n└─> ')
            if command == 'exit' or command == 'stop':
                print(colored("[!] Stopping console..", "yellow"))
                return
            else:
                self.execute_command(command.split())
        


if __name__ == '__main__':
    import argparse

    print(colored("[+] Starting console..", "green"))

    # INITIATING ARGUMENTS
    parser: argparse = argparse.ArgumentParser(description="Vulnerability scanner")

    parser.add_argument("-u", "--hostip", type=str, help="Host ip address")
    parser.add_argument("-p", "--hostport", type=int, help="Host port address")
    parser.add_argument("-r", "--hostportrange", type=int, help="Port range")
    parser.add_argument("-d", "--directories", type=str, help="Wordlist to directories")
    parser.add_argument("-s", "--subdomains", type=str, help="Wordlist to subdomains")

    args: argparse = parser.parse_args()

    #SET VALUES
    hostIP: str = args.hostip
    hostPort: int = args.hostport
    hostPortRange: int = args.hostportrange
    directories: str = args.directories
    subdomains: str = args.subdomains

    #DEFAULT VALUES
    if not hostIP:
        hostIP: str = "192.168.148.129/mutillidae"
    if not hostPort:
        hostPort: int = 80
    if not hostPortRange:
        hostPortRange: int = 80
    if not directories:
        directories: str = "/Discovery/DNS/subdomains-top1million-110000.txt"
    if not subdomains:
        subdomains: str = "/Discovery/DNS/subdomains-top1million-110000.txt"

    #RUNS VULNSCANNER
    try:
        Vulnscanner(hostIP=hostIP,
                    hostPort=hostPort,
                    hostPortRange=hostPortRange,
                    subdomains=subdomains,
                    directories=directories
                    ).console()
    except Exception as error:
        print(colored(f"[-] {error}..", "red"))

    print(colored("[-] Console has been stopped..", "red"))
