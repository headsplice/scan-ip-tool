import requests, sys, json,ipinfo,whois,ipaddress,os
ipinfoapikey = os.environ.get("IPINFOAPIKEY")
url = sys.argv[1]

try:
    if url == str(ipaddress.ip_address(url)):
        ipordomain = "ip"
except ValueError:
    ipordomain = "domain"

if ipordomain == "ip":
    lookup1 = requests.get("https://internetdb.shodan.io/"+url).json()
    print("ip: " + lookup1["ip"])
    print("cpes:")
    for cpe in lookup1['cpes']:
        print(" "+ cpe)
    for port in lookup1["ports"]:
        if port == 80:
            print("80   HTTP")
        if port == 443:
            print("443  HTTPS")
    if port == 20:
        print("20   FTP")
    if port == 21:
        print("21   FTP")
    if port == 22:
        print("22   SSH/SFTP")
    if port == 25:
        print("25   SMTP")
    if port == 110:
        print("110  POP3")
    if port == 143:
        print("143  IMAP")
    if port == 53:
        print("53   DNS")
    if port == 123:
        print("123  NTP")
    if port == 3389:
        print("3389 RDP")
    if port == 23:
        print("23   Telenet")
    else:
        print(port)
    print("detected vulnerability:")
    for vuln in lookup1['vulns']:
        print(vuln)

    print("tags:")
    for tag in lookup1["tags"]:
        print(tag)

    handler = ipinfo.getHandler(ipinfoapikey)

    geolocationdetails = handler.getDetails(url)
    print("city:    " + geolocationdetails.city)
    print("region:  " + geolocationdetails.region)
    print("country: " + geolocationdetails.country)
if ipordomain == "domain":
    whoisrequest = whois.whois(url)
    print("register: "+whoisrequest.registrar)


