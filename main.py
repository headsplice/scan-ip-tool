import requests, sys, json

ip = sys.argv[1]

lookup1 = requests.get("https://internetdb.shodan.io/"+ip).json()
print(lookup1)