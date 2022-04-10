# SSRF - Server-side request forgery

In a typical SSRF attack, the attacker might cause the server to make a connection to internal-only services within the organization's infrastructure. In other cases, they may be able to force the server to connect to arbitrary external systems, potentially leaking sensitive data such as authorization credentials.

## SSRF attacks against the server itself

In an SSRF attack against the server itself, the attacker induces the application to make an HTTP request back to the server that is hosting the application, via its loopback network interface. This will typically involve supplying a URL with a hostname like 127.0.0.1 (a reserved IP address that points to the loopback adapter) or localhost (a commonly used name for the same adapter).

### Basic SSRF against the local server

This lab has a stock check feature which fetches data from an internal system.
To solve the lab, change the stock check URL to access the admin interface at *http://localhost/admin* and delete the user carlos.

**Solution**
1. Browse to */admin* and observe that you can't directly access the admin page.
2. Visit a product, click "Check stock", intercept the request in Burp Suite, and send it to Burp Repeater.
3. Change the URL in the *stockApi* parameter to *http://localhost/admin*. This should display the administration interface.
4. Read the HTML to identify the URL to delete the target user, which is:

    ```http://localhost/admin/delete?username=carlos```

5. Submit this URL in the stockApi parameter, to deliver the SSRF attack.

**My comment**

Vulnerable feature - stock check functionality

Goal - change the stock check URL to access the admin interface at ```http://localhost/admin``` and delete the user carlos.

Analysis:

localhost - ```http://localhost/```

admin interface - ```http://localhost/admin```

delete carlost - ```http://localhost/admin/delete?username=carlos```

## SSRF attacks against other back-end systems

Like the administrative interface at the back-end URL is *https://192.168.0.X/admin* and I am able to find from 1 to 255 which server is it

### Basic SSRF against another back-end system

This lab has a stock check feature which fetches data from an internal system.
To solve the lab, use the stock check functionality to scan the internal *192.168.0.X* range for an admin interface on port 8080, then use it to delete the user *carlos*.

**Solution**
1. Visit a product, click "Check stock", intercept the request in Burp Suite, and send it to Burp Intruder.
2. Click "Clear §", change the *stockApi* parameter to ```http://192.168.0.1:8080/admin``` then highlight the final octet of the IP address (the number 1), click "Add §".
3. Switch to the Payloads tab, change the payload type to Numbers, and enter 1, 255, and 1 in the "From" and "To" and "Step" boxes respectively.
4. Click "Start attack".
5. Click on the "Status" column to sort it by status code ascending. You should see a single entry with a status of 200, showing an admin interface.
6. Click on this request, send it to Burp Repeater, and change the path in the *stockApi* to: ```/admin/delete?username=carlos```

**My comment**

ssrf-lab-02.py

## Circumventing common SSRF defenses

Some applications block input containing hostnames like *127.0.0.1* and *localhost*, or sensitive URLs like */admin*. In this situation, you can often circumvent the filter using various techniques:

- Using an alternative IP representation of *127.0.0.1*, such as *2130706433*, *017700000001*, or *127.1*.
- Registering your own domain name that resolves to *127.0.0.1*. You can use *spoofed.burpcollaborator.net* for this purpose.
- Obfuscating blocked strings using URL encoding or case variation.

### SSRF with blacklist-based input filter

This lab has a stock check feature which fetches data from an internal system.
To solve the lab, change the stock check URL to access the admin interface at *http://localhost/admin* and delete the user *carlos*.
The developer has deployed two weak anti-SSRF defenses that you will need to bypass.

**Solution**
1. Visit a product, click "Check stock", intercept the request in Burp Suite, and send it to Burp Repeater.
2. Change the URL in the *stockApi* parameter to *http://127.0.0.1/* and observe that the request is blocked.
3. Bypass the block by changing the URL to: *http://127.1/*
4. Change the URL to *http://127.1/admin* and observe that the URL is blocked again.
5. Obfuscate the "a" by double-URL encoding it to %2561 to access the admin interface and delete the target user.

**My comment**

ssrf-lab-03.py

## SSRF with whitelist-based input filters

Some applications only allow input that matches, you can use @ character, # character or . character. In this situation, you can sometimes circumvent the filter by exploiting inconsistencies in URL parsing.

The URL specification contains a number of features that are liable to be overlooked when implementing ad hoc parsing and validation of URLs:
- You can embed credentials in a URL before the hostname, using the @ character. For example:

    ```https://expected-host@evil-host```

- You can use the # character to indicate a URL fragment. For example:

    ```https://evil-host#expected-host```

- You can leverage the DNS naming hierarchy to place required input into a fully-qualified DNS name that you control. For example:

    ```https://expected-host.evil-host```

- You can URL-encode characters to confuse the URL-parsing code. This is particularly useful if the code that implements the filter handles URL-encoded characters differently than the code that performs the back-end HTTP request.
- You can use combinations of these techniques togethe

### SSRF with whitelist-based input filter

This lab has a stock check feature which fetches data from an internal system.
To solve the lab, change the stock check URL to access the admin interface at *http://localhost/admin* and delete the user *carlos*.
The developer has deployed an anti-SSRF defense you will need to bypass.

**Solution**
1. Visit a product, click "Check stock", intercept the request in Burp Suite, and send it to Burp Repeater.
2. Change the URL in the stockApi parameter to *http://127.0.0.1/* and observe that the application is parsing the URL, extracting the hostname, and validating it against a whitelist.
3. Change the URL to *http://username@stock.weliketoshop.net/* and observe that this is accepted, indicating that the URL parser supports embedded credentials.
4. Append a # to the username and observe that the URL is now rejected.
5. Double-URL encode the # to %2523 and observe the extremely suspicious "Internal Server Error" response, indicating that the server may have attempted to connect to "username".
6. To access the admin interface and delete the target user, change the URL to:

    ```http://localhost:80%2523@stock.weliketoshop.net/admin/delete?username=carlos```

**My comment**

ssrf-lab-04.py

## Bypassing SSRF filters via open redirection

 Application contains an open redirection vulnerability in which the following URL:
 
``` /product/nextProduct?currentProductId=6&path=http://evil-user.net ```

returns a redirection to:
```http://evil-user.net```

Cou can leverage the open redirection vulnerability to bypass the URL filter and exploit the SSRF vulnerability:

```stockApi=http://weliketoshop.net/product/nextProduct?currentProductId=6&path=http://192.168.0.68/admin```

### SSRF with filter bypass via open redirection vulnerability

This lab has a stock check feature which fetches data from an internal system.
To solve the lab, change the stock check URL to access the admin interface at *http://192.168.0.12:8080/admin* and delete the user *carlos*.
The stock checker has been restricted to only access the local application, so you will need to find an open redirect affecting the application first.

**Solution**
1. Visit a product, click "Check stock", intercept the request in Burp Suite, and send it to Burp Repeater.
2. Try tampering with the *stockApi* parameter and observe that it isn't possible to make the server issue the request directly to a different host.
3. Click "next product" and observe that the path parameter is placed into the Location header of a redirection response, resulting in an open redirection.
4. Create a URL that exploits the open redirection vulnerability, and redirects to the admin interface, and feed this into the *stockApi* parameter on the stock checker:

    ```/product/nextProduct?path=http://192.168.0.12:8080/admin```

5. Observe that the stock checker follows the redirection and shows you the admin page.
6. Amend the path to delete the target user:

    ```/product/nextProduct?path=http://192.168.0.12:8080/admin/```

**My comment**

ssrf-lab-05.py

## Blind SSRF vulnerabilities

Blind SSRF vulnerabilities arise when an application can be induced to issue a back-end HTTP request to a supplied URL, but the response from the back-end request is not returned in the application's front-end response.