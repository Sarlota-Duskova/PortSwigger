# Information disclosure vulnerabilities

Information disclosure, also known as information leakage, is when a website unintentionally reveals sensitive information to its users. Depending on the context, websites may leak all kinds of information to a potential attacker, including:
- Data about other users, such as usernames or financial information
- Sensitive commercial or business data
- Technical details about the website and its infrastructure

Some basic examples of information disclosure are as follows:
- Revealing the names of hidden directories, their structure, and their contents via a robots.txt file or directory listing
- Providing access to source code files via temporary backups
- Explicitly mentioning database table or column names in error messages
- Unnecessarily exposing highly sensitive information, such as credit card details
- Hard-coding API keys, IP addresses, database credentials, and so on in the source code
- Hinting at the existence or absence of resources, usernames, and so on via subtle differences in application behavior

## How do information disclosure vulnerabilities arise?

- **Failure to remove internal content from public content.** For example, developer comments in markup are sometimes visible to users in the production environment.
- **Insecure configuration of the website and related technologies.** For example, failing to disable debugging and diagnostic features can sometimes provide attackers with useful tools to help them obtain sensitive information. Default configurations can also leave websites vulnerable, for example, by displaying overly verbose error messages.
- **Flawed design and behavior of the application.** For example, if a website returns distinct responses when different error states occur, this can also allow attackers to enumerate sensitive data, such as valid user credentials.

### Fuzzing

In Burp Intruder can automate this process:

- Add payload positions to parameters and use pre-built wordlists of fuzz strings to test a high volume of different inputs in quick succession.
- Easily identify differences in responses by comparing HTTP status codes, response times, lengths, and so on.
- Use grep matching rules to quickly identify occurrences of keywords, such as error, invalid, SELECT, SQL, and so on.
- Apply grep extraction rules to extract and compare the content of interesting items within responses.

### Using Burp Scanner 

Burp Scanner will alert if it finds sensitive information such as private keys, email addresses, and credit card numbers in a response. It will also identify any backup files, directory listings, and so on.

## Common sources of information disclosure

The following are some common examples of places where you can look to see if sensitive information is exposed.

- Files for web crawlers
- Directory listings
- Developer comments
- Error messages
- Debugging data
- User account pages
- Backup files
- Insecure configuration 
- Version control history

### Files for web crawlers

Many websites provide files at */robots.txt* and */sitemap.xml* to help crawlers navigate their site. 

It is worth trying to navigate to */robots.txt* or */sitemap.xml* manually to see if you find anything of use.

### Directory listings

Directory listings themselves are not necessarily a security vulnerability. However, if the website also fails to implement proper access control, leaking the existence and location of sensitive resources in this way is clearly an issue.

### Developer comments

Comments can sometimes be forgotten, missed, or even left in deliberately. 

Occasionally, these comments contain information that is useful to an attacker. For example, they might hint at the existence of hidden directories or provide clues about the application logic.

### Error messages

The content of error messages can reveal information about what input or data type is expected from a given parameter. This can help you to narrow down your attack by identifying exploitable parameters. It may even just prevent you from wasting time trying to inject payloads that simply won't work.

### Information disclosure in error messages

This lab's verbose error messages reveal that it is using a vulnerable version of a third-party framework. 

**Solution**

1. With Burp running, open one of the product pages.
2. In Burp, go to "Proxy" > "HTTP history" and notice that the *GET* request for product pages contains a *productID* parameter. Send the *GET /product?productId=1* request to Burp Repeater. Note that your *productId* might be different depending on which product page you loaded.
3. In Burp Repeater, change the value of the *productId* parameter to a non-integer data type, such as a string. Send the request:

    ```GET /product?productId="example"```

4. The unexpected data type causes an exception, and a full stack trace is displayed in the response. This reveals that the lab is using Apache Struts 2 2.3.31.
5. Go back to the lab, click "Submit solution", and enter **2 2.3.31** to solve the lab.

### Debugging data

For debugging purposes, many websites generate custom error messages and logs that contain large amounts of information about the application's behavior.

Debug messages can sometimes contain vital information for developing an attack, including:
- Values for key session variables that can be manipulated via user input
- Hostnames and credentials for back-end components
- File and directory names on the server
- Keys used to encrypt data transmitted via the client

### Information disclosure on debug page

This lab contains a debug page that discloses sensitive information about the application. 

**Solution**

1. With Burp running, browse to the home page.
2. Go to the "Target" > "Site Map" tab. Right-click on the top-level entry for the lab and select "Engagement tools" > "Find comments". Notice that the home page contains an HTML comment that contains a link called "Debug". This points to */cgi-bin/phpinfo.php.*
3. In the site map, right-click on the entry for */cgi-bin/phpinfo.php* and select "Send to Repeater".
4. In Burp Repeater, send the request to retrieve the file. Notice that it reveals various debugging information, including the *SECRET_KEY* environment variable.
5. Go back to the lab, click "Submit solution", and enter the *SECRET_KEY* to solve the lab.

### User account pages

Some websites contain logic flaws that potentially allow an attacker to leverage these pages in order to view other users' data.
For example, consider a website that determines which user's account page to load based on a user parameter.

```GET /user/personal-info?user=carlos```

**Continue in 2-Access control.**

### Source code disclosure via backup files

Text editors often generate temporary backup files while the original file is being edited. These temporary files are usually indicated in some way, such as by appending a tilde (~) to the filename or adding a different file extension. Requesting a code file using a backup file extension can sometimes allow you to read the contents of the file in the response.

### Source code disclosure via backup files

This lab leaks its source code via backup files in a hidden directory.

**Solution**

1. Browse to */robots.txt* and notice that it reveals the existence of a /backup directory. Browse to */backup* to find the file *ProductTemplate.java.bak*. Alternatively, right-click on the lab in the site map and go to "Engagement tools" > "Discover content". Then, launch a content discovery session to discover the */backup* directory and its contents.
2. Browse to */backup/ProductTemplate.java.bak* to access the source code.
3. In the source code, notice that the connection builder contains the hard-coded password for a Postgres database.
4. Go back to the lab, click "Submit solution", and enter the database password to solve the lab.

**Continue in 3-Insecure deserialization.**

### Information disclosure due to insecure configuration

developers might forget to disable various debugging options in the production environment. For example, the HTTP TRACE method is designed for diagnostic purposes. If enabled, the web server will respond to requests that use the TRACE method by echoing in the response the exact request that was received. This behavior is often harmless, but occasionally leads to information disclosure, such as the name of internal authentication headers that may be appended to requests by reverse proxies.

### Authentication bypass via information disclosure

This lab's administration interface has an authentication bypass vulnerability, but it is impractical to exploit without knowledge of a custom HTTP header used by the front-end.

**Solution**

1. In Burp Repeater, browse to *GET /admin*. The response discloses that the admin panel is only accessible if logged in as an administrator, or if requested from a local IP.
2. Send the request again, but this time use the *TRACE* method:

    ```TRACE /admin```

3. Study the response. Notice that the *X-Custom-IP-Authorization* header, containing your IP address, was automatically appended to your request. This is used to determine whether or not the request came from the *localhost* IP address.
4. Go to "Proxy" > "Options", scroll down to the "Match and Replace" section, and click "Add". Leave the match condition blank, but in the "Replace" field, enter:

    ```X-Custom-IP-Authorization: 127.0.0.1```

    Burp Proxy will now add this header to every request you send.
5. Browse to the home page. Notice that you now have access to the admin panel, where you can delete Carlos.

### Version control history

Virtually all websites are developed using some form of version control system, such as Git. By default, a Git project stores all of its version control data in a folder called .git. Occasionally, websites expose this directory in the production environment. In this case, you might be able to access it by simply browsing to /.git.

### Information disclosure in version control history

This lab discloses sensitive information via its version control history. 

**Solution**

1. Open the lab and browse to */.git* to reveal the lab's Git version control data.
2. Download a copy of this entire directory. For Linux users, the easiest way to do this is using the command:

    ```wget -r https://your-lab-id.web-security-academy.net/.git/```

    Windows users will need to find an alternative method, or install a UNIX-like environment, such as Cygwin, in order to use this command.
3. Explore the downloaded directory using your local Git installation. Notice that there is a commit with the message "Remove admin password from config".
4. Look closer at the diff for the changed *admin.conf* file. Notice that the commit replaced the hard-coded admin password with an environment variable *ADMIN_PASSWORD* instead. However, the hard-coded password is still clearly visible in the diff.
5. Go back to the lab and log in to the administrator account using the leaked password.
6. To solve the lab, open the admin interface and delete Carlos's account.
