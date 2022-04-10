# Subverting application logic

If a user submits the username *wiener* and password *bluecheeses*, the application checks the credentials by performing the following SQL query:

``` SELECT * FROM users WHERE username = 'wiener' AND password = 'bluecheese' ```

Here it can be use comment sequence -- to remove the password check from the *WHERE* clause of the query. For example, submitting the username ``` administrator'--``` and a blank password results in the following query:

``` SELECT * FROM users WHERE username = 'administrator'--' AND password = '' ```

This query returns the user whose username is *administrator* and successfully logs in.

### SQL injection vulnerability alloqing login bypass

This lab contains an SQL injection vulnerability in the login function.

**Solution**

1. Use Burp Suite to intercept and modify the login request.
2. Modify the *username* parameter, giving it the value: ``` administrator'--```