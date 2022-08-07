import whois
import dns.resolver
import shodan
import requests 
import argparse
import socket 

argparse = argparse.ArgumentParser(description="Basic information gathering tool by Dhairya", usage = "python3 info_gathering.py -d DOMAIN [-s IP]")

argparse.add_argument("-d", "--domain", help="Enter the domain name for footprinting.")
argparse.add_argument("-s", "--shodan", help="Enter the IP for shodan search.")
argparse.add_argument("-o", "--output", help="Enter the file to write output to.")

args = argparse.parse_args()

domain = args.domain 
ip = args.shodan
output = args.output

# whois module
print("[+] Getting whois info...")
whois_result = ''
try:
    py = whois.query(domain)
    # print("[+] whois info found.")
    # print("Name: {}".format(py.name))
    # print("Registrar: {}".format(py.registrar))
    # print("Creation Date: {}".format(py.creation_date))
    # print("Expiration Date: {}".format(py.expiration_date))
    # print("Registrant: {}".format(py.registrant))
    # print("Registrant Country: {}".format(py.registrant_country))

    whois_result += "Name: {}".format(py.name) + '\n'   # append
    whois_result += "Registrar: {}".format(py.registrar) + '\n'
    whois_result += "Creation Date: {}".format(py.creation_date) + '\n'
    whois_result += "Expiration Date: {}".format(py.expiration_date) + '\n'
    whois_result += "Registrant: {}".format(py.registrant) + '\n'
    whois_result += "Registrant Country: {}".format(py.registrant_country) + '\n'
except:
    pass
print(whois_result)

# DNS module
print("[+] Getting DNS info...")
dns_result = ''

# Implementing dns.resolver from dnspython
try:
    for a in dns.resolver.resolve(domain, "A"): # fetching every A record from domain
        dns_result += "A Record: " + a.to_text() + '\n'
    for ns in dns.resolver.resolve(domain, "NS"):
        dns_result += "NS Record: " + ns.to_text() + '\n'
    for mx in dns.resolver.resolve(domain, "MX"):
        dns_result += "MX Record: " + mx.to_text() + '\n'
    for txt in dns.resolver.resolve(domain, "TXT"):
        dns_result += "TXT Record: " + txt.to_text() + '\n'
except:
    pass
print(dns_result)

# Geolocation module
print("[+] Getting Geolocation info...")
geo_result = ''

# Implementing requests for web request
try:
    response = requests.request('GET', "https://geolocation-db.com/json/" + socket.gethostbyname(domain)).json()
    geo_result += "[+] Country: {} ".format(response['country_name']) + '\n'
    geo_result += "[+] Latitude: {}".format(response['latitude']) + '\n'
    geo_result += "[+] Longitude: {}".format(response['longitude']) + '\n'
    geo_result += "[+] State: {}".format(response['state']) + '\n'
    geo_result += "[+] City: {}".format(response['city']) + '\n'
except:
    pass


# Shodan module
if ip:
    print("[+] Getting info from shodan for IP".format(ip))

    # Shodan API
    api = shodan.Shodan("HMFNf6R4yOafsU60AF2xMy4K3qW443HX")
    try:
        results = api.search(ip)
        print("[+] Results found: {}".format(results['total']))
        for result in results['matches']:
            print("[+] IP: {}".format(result['ip_str']))
            print("[+] Data: \n{}".format(result['data']))
            print()
    except:
        print("[-] Shodan search error.")

if(output):
    with open(output, 'w') as file:
        file.write(whois_result + '\n\n')
        file.write(dns_result + '\n\n')
        file.write(geo_result + '\n\n')
