import requests, sys, json

ip = sys.argv[1]

lookup1 = requests.get("https://internetdb.shodan.io/"+ip).json()
print("ip:" + lookup1["ip"])
print("open ports:")
for port in lookup1["ports"]:
    print(port)

print("detected vulnerability:")
for vuln in lookup1['vulns']:
    print(vuln)

print("tags:")
for tag in lookup1["tags"]:
    print(tag)