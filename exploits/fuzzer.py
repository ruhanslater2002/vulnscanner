import requests
import time
from termcolor import colored

class Fuzzer:
    def __init__(self, url: str, subdomains: str, directories: str, threads=0) -> None:
        self.url: str = str(url)
        self.subdomains: str = str(subdomains)
        self.directories: str = str(directories)
        self.threads: float = float(threads)


    def request_code(self) -> int:
        try:
            return requests.get(url="http://" + self.url)
            time.sleep(self.threads)
        except requests.exceptions.ConnectionError:
            return


    def dir_fuzz(self) -> None:
        url: str = self.url
        with open(self.directories, "r") as wordlist:
            for word in wordlist:
                word = word.strip()
                self.url = url + "/" + word
                try:
                    response: requests = self.request_code()
                except Exception as error:
                    print(colored(f"[-] {error}", "red"))
                    print(colored(f"[!] Waiting 5 seconds..", "yellow"))
                    time.sleep(5)
                if response:
                    print(colored(f"[+] found -> {self.url}", "green"))


    def subd_fuzz(self, dirFuzz=False) -> bool:
        url: str = self.url
        subDomainFound: bool = False
        with open(self.subdomains, "r") as wordlist:
            for word in wordlist:
                word = word.strip()
                self.url = word + "." + url
                try:
                    response: requests = self.request_code()
                except Exception as error:
                    print(colored(f"[-] {error}", "red"))
                    print(colored(f"[!] Waiting 5 seconds..", "yellow"))
                    time.sleep(5)
                if response:
                    subDomainFound: bool = True
                    print(colored(f"[+] found -> {self.url}", "green"))
                    if bool(dirFuzz) == True:
                        self.dir_fuzz()
        return subDomainFound


    def fuzz(self) -> None:
        print(colored(f"[+] Fuzzing {self.url}", "green"))
        url: str = self.url
        subDomainFound: bool = self.subd_fuzz(dirFuzz=True)
        if bool(subDomainFound) == False:
            print(colored("[!] Couln't fuzz sub domains, fuzzing directories..", "yellow"))
            self.url: str = url
            self.dir_fuzz()


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description="Fuzzing hidden paths on a website")
    parser.add_argument("-u", "--url", type=str, help="URL to perform fuzzing")
    parser.add_argument("-s", "--subdomains", type=str, help="Wordlist of subdomains")
    parser.add_argument("-d", "--directories", type=str, help="Wordlist of directories")
    parser.add_argument("-t", "--threads", type=int, help="Number of threads")

    args = parser.parse_args()

    url: str = args.url
    subdomains: str = args.subdomains
    directories: str = args.directories
    threads: int = args.threads

    if not url:
        url: str = "192.168.0.1"

    if not subdomains:
        subdomains: str = "C:/Users/ruhan/PythonProjects/vulnscanner/other/Discovery/DNS/subdomains-top1million-110000.txt"

    if not directories:
        directories: str = "C:/Users/ruhan/PythonProjects/vulnscanner/other/Discovery/DNS/subdomains-top1million-110000.txt"

    if not threads:
        threads: int = 0

    try:
        Fuzzer(url=url, subdomains=subdomains, directories=directories, threads=threads).fuzz()

    except Exception as error:
        print(colored(f"[-] {error}", "red"))
