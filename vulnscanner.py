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
    print(colored("[+] Starting console..", "green"))

    #DEFAULT VALUES
    hostIP: str = "192.168.148.129/mutillidae"
    hostPort: int = 80
    hostPortRange: int = 80
    directories: str = None
    subdomains: str = None

    #RUNS VULNSCANNER
    try:
        Vulnscanner(hostIP=sys.argv[1],
                    hostPort=sys.argv[2],
                    hostPortRange=sys.argv[3]
                    ).scan(exploit=sys.argv[4])
    except:
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
