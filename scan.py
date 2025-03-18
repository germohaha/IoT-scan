'''
A Basic Internet Of Things scanning tool which scan devices using SSH or telnet sevices and then test for default creds. 
'''
import requests
import json #for fomatting 
import shodan
import nmap
import subprocess
import time
from colorama import Fore,Style, init
import concurrent.futures as threads


init(autoreset=True)#make sure it only colors the defined variable

APIkey = "l7mM72OnWWnFMUvBnfNCBLilpNK60XK2"
zoomeyekey = "input here"
censysID = "input here"
censys_sec = "yes here too"
api = shodan.Shodan(APIkey)


def iot(limit=100):
    ips = []
    query = 'port:22 OR port:23 OR port:80 OR "webcam"'
    try:
        res = shodan_api.search(query, limit=limit)  
        ips = [result["ip_str"] for result in res["matches"]]
        device.append(ips)
    except shodan.APIError as e:
        print(f"Shodan API error: {e}")
    return []


def zoomeye():
    list = {
        ee == '{"Authorization": "Bearer{zoomeyekey}}',
        var4 == dict(json.loads(ee))
}
var2 = f'https://api.zoomeye.org/host/search'
params = {'query': 'port:22 OR port:23'}

try:
        # Send request to Zoomeye API
        response = requests.get(var2, headers=list, params=params)
        response.raise_for_status()  # Raises HTTPError for bad responses (4xx, 5xx)
        if response.status_code != 200:
            print(f"Error in {response.text}, maybe input an API key?")

        data = response.json()  # Parse JSON response

        ips = []
        for result in data.get('matches', []):  
            ip = result['ip']
            ips.append(ip)
        print(zoomeye())

except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")

finally:
    print("completed!!")
        # debug for zoomeye func

        #censys IoT API func
def cen():
    url = "https://search.censys.io/api/v1/search/ipv4"
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Basic {censysid}:{censys_sec}'
    }
    body = {
        "query": "ports:22 OR ports:23",
        "page": 2,
        "per": 10
    }
    #requests iteration
    try: 
        
        drake = requests.post(url, json=body, headers=headers)
        drake.raise_for_status()  # Check for request errors
        
        # parse using json 
        data = drake.json()
        ips = []
        
        # IP's from API
        for result in data.get('results', []):
            ip = result['ip']
            ips.append(ip)
        
        return ips  # Return the list of IPs 

    except requests.exceptions.RequestException as e:
        print(f"Error during request: {e}")
        return []  # Return an empty list on error

    finally:
        # This will run no matter what 
        print("DABUG?")
# debug func


# Nmap scanning func
def nmap(ips):
    nm = nmap.PortScanner()
    value = {}
    info = {}  # Initialize info to store service details

    for ip in ips:
        try:
            nm.scan(ip, '22,23', arguments='-A -sV')  # Correct function call
            value[ip] = []

            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        stat = nm[host][proto][port]['state']

                        if stat == 'open':
                            service = nm[host][proto][port]['name']
                            ver = nm[host][proto][port].get('version', 'Unknown')
                            if ip not in info:
                                info[ip] = {}
                            info[ip][port] = f"{service} ({ver})"
                            value[ip].append(port)
                        else:
                            print(f"BATMAN: device IP {ip} port {port} is closed, moving on.")
            
            if value[ip]:
                print(f"BATMAN: services for {ip}: {info[ip]}")
            else:
                print(f"BATMAN: no open ports found on {ip}")

        except Exception as e:
            print(f"Error scanning {ip}: {e}")
    
    return value  # Return value after processing all IPs

def threads(main_ips):
    info = {}

    with ThreadPoolExecutor(max_workers=10) as executor:
        output = executor.map(nmap_scan, main_ips)
        for result in output:
            if result:
                info.update(result)  # Merge the result into info
    return info



def main():
    art = """


"""
print(Fore.RED + art)
shodan  =  iot()
zoomeye2 = doomeye()
censys2 = cen()
binaryedge = edge()
fofa = fofa()
main_ips = list(set(shodan + zoomeye2 + censys2 + binaryedge + fofa))
if main_ips:
    print(f"BATMAN: device IP's found: {len(main_ips)}")
    ports = threads(main_ips)
    
print("BATMAN SCANNED!!!!: ")
for ip,services in main_ips.items():
    for new, service in services.item():
        print(f"BATMAN:{ip}:{new} -->> {services}")
if __name__ == "__main__":
    main()
