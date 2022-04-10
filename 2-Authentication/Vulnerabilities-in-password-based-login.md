# Vulnerabilities in password-based login

## Brute-force attacks

A brute-force attack is when an attacker uses a system of trial and error in an attempt to quess valid user credentials. These attacks are typically automated using wordlists of usernames and passwords. 

### Brute-forcing usernames

Usernames are especially easy to guess if they conform to a recognizable pattern, such as an email address. 

### Brute-forcing passwords

Many websites adopt some form of password policy, which forces users to create high-entropy passwords. This typically involves enforcing passwords with:
- A minimum number of characters
- A mixture of lower and uppercase letters
- At least one special character

## Username enumeration

Username enumeration is when an attacker is able to observe changes in the website's behavior in order to identify whether a given username is valid.

While attempting to brute-forcre a login page, you should pay particular attention to any differences in:

- **Status codes** during a brute-force attack, the returned HTTP status code is likely to be the same for the vast majority of guesses because most of them will be wrong. If a guess returns a different status code, this is a strong indication that the username was correct.
- **Error messages** sometimes the returned error message is different depending on whether both the username AND password are incorrect or only the password was incorrect.
- **Response times** if most of the requests were handled with a similar response time, any that deviate from this suggest that something different was happening behind the scenes.

### Username enumeration via different responses

**Solution**
1. With Burp running, investigate the login page and submit an invalid username and password.
2. In Burp, go to **Proxy > HTTP history** and find the *POST /login* request. Send this to Burp Intruder.
3. In Burp Intruder, go to the **Positions** tab. Make sure that the **Sniper** attack type is selected.
4. Click **Clear §** to remove any automatically assigned payload positions. Highlight the value of the username parameter and click **Add §** to set it as a payload position. This position will be indicated by two § symbols, for example: *username=§invalid-username§*. Leave the password as any static value for now.
5. On the **Payloads** tab, make sure that the **Simple list** payload type is selected.
6. Under **Payload options**, paste the list of candidate usernames. Finally, click **Start attack**. The attack will start in a new window.
7. When the attack is finished, on the **Results** tab, examine the **Length** column. You can click on the column header to sort the results. Notice that one of the entries is longer than the others. Compare the response to this payload with the other responses. Notice that other responses contain the message *Invalid username*, but this response says *Incorrect password*. Make a note of the username in the **Payload** column.
8. Close the attack and go back to the **Positions** tab. Click **Clear**, then change the username parameter to the username you just identified. Add a payload position to the password parameter. The result should look something like this:

    ``` username=identified-user&password=§invalid-password§ ```

9. On the **Payloads** tab, clear the list of usernames and replace it with the list of candidate passwords. Click **Start attack**.
10. When the attack is finished, look at the **Status** column. Notice that each request received a response with a 200 status code except for one, which got a 302 response. This suggests that the login attempt was successful - make a note of the password in the **Payload** column.
11. Log in using the username and password that you identified and access the user account page to solve the lab.

**My comment**

First try random username and password then in Burp find in Proxy in HTTP history POST request and send it to Intruder  go to the "Positions" tab. and select "Sniper" attack type. On the "Payloads" tab select "Simple list" payload type then Under "Payload options", paste the list of candidate usernames. Finally, click "Start attack". 

### Username enumeration via subtly different responses

**Solution**
1. With Burp running, submit an invalid username and password. Send the *POST /login* request to Burp Intruder and add a payload position to the username parameter.
2. On the **Payloads** tab, make sure that the **Simple list** payload type is selected and add the list of candidate usernames.
3. On the **Options** tab, under **Grep - Extract**, click **Add**. In the dialog that appears, scroll down through the response until you find the error message Invalid username or password.. Use the mouse to highlight the text content of the message. The other settings will be automatically adjusted. Click **OK** and then start the attack.
4. When the attack is finished, notice that there is an additional column containing the error message you extracted. Sort the results using this column to notice that one of them is subtly different.
5. Look closer at this response and notice that it contains a typo in the error message - instead of a full stop/period, there is a trailing space. Make a note of this username.
6. Close the attack and go back to the **Positions** tab. Insert the username you just identified and add a payload position to the password parameter:

    ``` username=identified-user&password=§invalid-password§ ```

7. On the **Payloads** tab, clear the list of usernames and replace it with the list of passwords. Start the attack.
8. When the attack is finished, notice that one of the requests received a 302 response. Make a note of this password.
9. Log in using the username and password that you identified and access the user account page to solve the lab.

**My comments**

Try random username and password then in Burp find in Proxy in HTTP history POST request and send it to Intruder. go to the "Positions" tab. and select "Sniper" attack type. On the "Payloads" tab select "Simple list" payload type then Under "Payload options", paste the list of candidate usernames. On the "Options" tab, under "Grep - Extract", click "Add". In the dialog that appears, scroll down through the response until you find the error message Invalid username or password. Use the mouse to highlight the text content of the message. Start the attack.

### Username enumeration via response timing

**Solution**
1. With Burp running, submit an invalid username and password, then send the *POST /login* request to Burp Repeater. Experiment with different usernames and passwords. Notice that your IP will be blocked if you make too many invalid login attempts.
2. Identify that the *X-Forwarded-For* header is supported, which allows you to spoof your IP address and bypass the IP-based brute-force protection.
3. Continue experimenting with usernames and passwords. Pay particular attention to the response times. Notice that when the username is invalid, the response time is roughly the same. However, when you enter a valid username (your own), the response time is increased depending on the length of the password you entered.
4. Send this request to Burp Intruder and select the attack type to **Pitchfork**. Clear the default payload positions and add the *X-Forwarded-For* header.
5. Add payload positions for the *X-Forwarded-For* header and the username parameter. Set the password to a very long string of characters (about 100 characters should do it).
6. On the **Payloads** tab, select payload set 1. Select the **Numbers** payload type. Enter the range 1 - 100 and set the step to 1. Set the max fraction digits to 0. This will be used to spoof your IP.
7. Select payload set 2 and add the list of usernames. Start the attack.
8. When the attack finishes, at the top of the dialog, click **Columns** and select the **Response received** and **Response completed** options. These two columns are now displayed in the results table.
9. Notice that one of the response times was significantly longer than the others. Repeat this request a few times to make sure it consistently takes longer, then make a note of this username.
10. Create a new Burp Intruder attack for the same request. Add the *X-Forwarded-For* header again and add a payload position to it. Insert the username that you just identified and add a payload position to the *password* parameter.
11. On the **Payloads** tab, add the list of numbers in payload set 1 and add the list of passwords to payload set 2. Start the attack.
12. When the attack is finished, find the response with a *302* status. Make a note of this password.
13. Log in using the username and password that you identified and access the user account page to solve the lab.

## Flawed brute-force protection

It is highly likely that a brute-force attack will involve many failed guesses before the attacker successfully compromises an account. Logically, brute-force protection revolves around trying to make it as tricky as possible to automate the process and slow down the rate at which an attacker can attempt logins. The two most common ways of preventing brute-force attacks are:

- Locking the account that the remote user is trying to access if they make too many failed login attempts.
- Blocking the remote user's IP address if they make too many login attempts in quick succession.

For example, you might sometimes find that your IP is blocked if you fail to log in too many times. In some implementations, the counter for the number of failed attempts resets if the IP owner logs in successfully. This means an attacker would simply have to log in to their own account every few attempts to prevent this limit from ever being reached.

### Broken brute-force protection, IP block

**Solution**
1. With Burp running, investigate the login page. Observe that your IP is temporarily blocked if you submit 3 incorrect logins in a row. However, notice that you can reset the counter for the number of failed login attempts by logging in to your own account before this limit is reached.
2. Enter an invalid username and password, then send the *POST /login* request to Burp Intruder. Create a pitchfork attack with payload positions in both the *username* and *password* parameters.
3. On the **Resource pool** tab, add the attack to a resource pool with **Maximum concurrent requests** set to 1. By only sending one request at a time, you can ensure that your login attempts are sent to the server in the correct order.
4. On the **Payloads** tab, select payload set 1. Add a list of payloads that alternates between your username and *carlos*. Make sure that your username is first and that *carlos* is repeated at least 100 times.
5. Edit the list of candidate passwords and add your own password before each one. Make sure that your password is aligned with your username in the other list.
6. Add this list to payload set 2 and start the attack.
7. When the attack finishes, filter the results to hide responses with a 200 status code. Sort the remaining results by username. There should only be a single 302 response for requests with the username *carlos*. Make a note of the password from the **Payload 2** column.
8. Log in to Carlos's account using the password that you identified and access his account page to solve the lab.

**My comment**

Create list with correct password and password and credential name and victim name and set Intruder to Pitchfork

HTTP Strict Transport Security (HSTS) je v informatice bezpečnostní mechanismus, který chrání síťovou komunikaci mezi webovým prohlížečem a webovým serverem před downgrade útoky a zjednodušuje ochranu proti únosu spojení (tzv. cookie hijacking). Mechanismus umožňuje, aby webový server vynutil v prohlížeči komunikaci pouze pomocí šifrovaného HTTPS připojení a vyloučil tím přenos dat nezabezpečeným HTTP protokolem. 

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           requestsPerConnection=100,
                           pipeline=False
                           )
    
    for i in range(1, 8):
        #engine.queue(target.req, randstr(i), learn=1)
        #engine.queue(target.req, target.baseInput, learn=2)

        #pokus
        #engine.queue(target.req, str(i))
        list_abc = ['carlos','root','admin','test','guest','info','adm','mysql','user','administrator','oracle','ftp','pi','puppet','ansible','ec2-user','vagrant','azureuser','academico','acceso','access','accounting','accounts','acid','activestat','ad','adam','adkit','admin','administracion','administrador','administrator','administrators','admins','ads','adserver','adsl','ae','af','affiliate','affiliates','afiliados','ag','agenda','agent','ai','aix','ajax','ak','akamai','al','alabama','alaska','albuquerque','alerts','alpha','alterwind','am','amarillo','americas','an','anaheim','analyzer','announce','announcements','antivirus','ao','ap','apache','apollo','app','app01','app1','apple','application','applications','apps','appserver','aq','ar','archie','arcsight','argentina','arizona','arkansas','arlington','as','as400','asia','asterix','at','athena','atlanta','atlas','att','au','auction','austin','auth','auto','autodiscover']
        for j in list_abc:
            engine.queue(target.req, [str(i), j])

    for word in open('/usr/share/dict/words'):
        engine.queue(target.req, word.rstrip())


def handleResponse(req, interesting):
    if interesting:
        table.add(req)
```

## Acount locking

One way in which websites try to prevent brute-forcing is to lock the account if certain suspicious criteria are met, usually a set number of failed login attempts. Just as with normal login errors, responses from the server indicating that an account is locked can also help an attacker to enumerate usernames.

### Username enumeration via account lock

**Solution**
1. With Burp running, investigate the login page and submit an invalid username and password. Send the *POST /login* request to Burp Intruder.
2. Select the attack type **Cluster bomb**. Add a payload position to the username parameter. Add a blank payload position to the end of the request body by clicking **Add §** twice. The result should look something like this:

    ``` username=§invalid-username§&password=example§§ ```

3. On the **Payloads** tab, add the list of usernames to the first payload set. For the second set, select the **Null payloads** type and choose the option to generate 5 payloads. This will effectively cause each username to be repeated 5 times. Start the attack.
4. In the results, notice that the responses for one of the usernames were longer than responses when using other usernames. Study the response more closely and notice that it contains a different error message: You have made too many *incorrect login attempts*. Make a note of this username.
5. Create a new Burp Intruder attack on the *POST /login* request, but this time select the **Sniper** attack type. Set the *username* parameter to the username that you just identified and add a payload position to the *password* parameter.
6. Add the list of passwords to the payload set and create a grep extraction rule for the error message. Start the attack.
7. In the results, look at the grep extract column. Notice that there are a couple of different error messages, but one of the responses did not contain any error message. Make a note of this password.
8. Wait for a minute to allow the account lock to reset. Log in using the username and password that you identified and access the user account page to solve the lab.

## User rate limiting

Another way websites try to prevent brute-force attacks is through user rate limiting. In this case, making too many login requests within a short period of time causes your IP address to be blocked. Typically, the IP can only be unblocked in one of the following ways:

- Automatically after a certain period of time has elapsed
- Manually by an administrator
- Manually by the user after successfully completing a CAPTCHA

### Broken brute-force protection, multiple credentials per request

1. With Burp running, investigate the login page. Notice that the *POST /login* request submits the login credentials in *JSON* format. Send this request to Burp Repeater.
2. In Burp Repeater, replace the single string value of the password with an array of strings containing all of the candidate passwords. For example:

    ``` json
    "username" : "carlos",
    "password" : [
        "123456",
        "password",
        "qwerty"
        ...
    ]
    ```
    
3. Send the request. This will return a 302 response.
4. Right-click on this request and select **Show response in browser**. Copy the URL and load it in your browser. The page loads and you are logged in as *carlos*.
5. Click **My account** to access Carlos's account page and solve the lab.

## HTTP basic authentication

In HTTP basic authentication, the client receives an authentication token from the server, which is constructed by concatenating the username and password, and encoding it in Base64. This token is stored and managed by the browser, which automatically adds it to the *Authorization* header of every subsequent request as follows:

``` Authorization: Basic base64(username:password) ```

For a number of reasons, this is generally not considered a secure authentication method. Firstly, it involves repeatedly sending the user's login credentials with every request. Unless the website also implements HSTS, user credentials are open to being captured in a man-in-the-middle attack.