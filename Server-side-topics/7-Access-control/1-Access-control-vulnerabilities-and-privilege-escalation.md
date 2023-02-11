# Access control vulnerabilities and privilege escalation

## Access control

Access control (or authorization) is the application of constraints on who (or what) can perform attempted actions or access resources that they have requested.

- **Authentication** identifies the user and confirms that they are who they say they are.
- **Session management** identifies which subsequent HTTP requests are being made by that same user.
- **Access control** determines whether the user is allowed to carry out the action that they are attempting to perform.

From a user perspective, access controls can be divided into the following categories:
- Vertical access controls
- Horizontal access controls
- Context-dependent access controls

## Vertical access controls

Vertical access controls are mechanisms that restrict access to sensitive functionality that is not available to other types of users.

With vertical access controls, different types of users have access to different application functions. For example, an administrator might be able to modify or delete any user's account, while an ordinary user has no access to these actions.

## Horizontal access controls

Horizontal access controls are mechanisms that restrict access to resources to the users who are specifically allowed to access those resources.

With horizontal access controls, different users have access to a subset of resources of the same type. For example, a banking application will allow a user to view transactions and make payments from their own accounts, but not the accounts of any other user.

## Context-dependent access controls

Context-dependent access controls restrict access to functionality and resources based upon the state of the application or the user's interaction with it.

Context-dependent access controls prevent a user performing actions in the wrong order. For example, a retail website might prevent users from modifying the contents of their shopping cart after they have made payment.

# Examples of broken access controls

Broken access control vulnerabilities exist when a user can in fact access some resource or perform some action that they are not supposed to be able to access.

## Vertical privilege escalation

If a user can gain access to functionality that they are not permitted to access then this is vertical privilege escalation. For example, if a non-administrative user can in fact gain access to an admin page where they can delete user accounts, then this is vertical privilege escalation.

## Unprotected functionality

For example, administrative functions might be linked from an administrator's welcome page but not from a user's welcome page. However, a user might simply be able to access the administrative functions by browsing directly to the relevant admin URL.

### Unprotected admin functionality

This lab has an unprotected admin panel.

**Solution:**
1. Go to the lab and view robots.txt by appending */robots.txt* to the lab URL. Notice that the Disallow line discloses the path to the admin panel.
2. In the URL bar, replace */robots.txt* with */administrator-panel* to load the admin panel.
3. Delete carlos.

### Unprotected admin functionality with unpredictable URL

This lab has an unprotected admin panel. It's located at an unpredictable location, but the location is disclosed somewhere in the application.

**Solution:**
1. Review the lab home page's source using Burp Suite or your web browser's developer tools.
2. Observe that it contains some JavaScript that discloses the URL of the admin panel.
3. Load the admin panel and delete carlos.

## Parameter-basec access control methods

Some applications determine the user's access rights or role at login, and then store this information in a user-controllable location, such as a hidden field, cookie, or preset query string parameter. The application makes subsequent access control decisions based on the submitted value. For example:

```
https://insecure-website.com/login/home.jsp?admin=true
https://insecure-website.com/login/home.jsp?role=1
```

### User role controlled by request parameter

This lab has an admin panel at /admin, which identifies administrators using a forgeable cookie.

**Solution:**
1. Browse to */admin* and observe that you can't access the admin panel.
2. Browse to the login page.
3. In Burp Proxy, turn interception on and enable response interception.
4. Complete and submit the login page, and forward the resulting request in Burp.
5. Observe that the response sets the cookie *Admin=false*. Change it to *Admin=true*.
6. Load the admin panel and delete *carlos*.

### User role can be modified in user profile

This lab has an admin panel at /admin. It's only accessible to logged-in users with a roleid of 2.

**Solution:**
1. Log in using the supplied credentials and access your account page.
2. Use the provided feature to update the email address associated with your account.
3. Observe that the response contains your role ID.
4. Send the email submission request to Burp Repeater, add *"roleid":2* into the JSON in the request body, and resend it.
5. Observe that the response shows your *roleid* has changed to 2.
6. Browse to */admin* and delete *carlos*.

## Broken access control resulting from platborm misconfiguration

Some applications enforce access controls at the platform layer by restricting access to specific URLs and HTTP methods based on the user's role. For example an application might configure rules like the following:

```DENY: POST, /admin/deleteUser, managers```

Some application frameworks support various non-standard HTTP headers that can be used to override the URL in the original request, such as X-Original-URL and X-Rewrite-URL. If a web site uses rigorous front-end controls to restrict access based on URL, but the application allows the URL to be overridden via a request header, then it might be possible to bypass the access controls using a request like the following:

```
POST / HTTP/1.1
X-Original-URL: /admin/deleteUser
...
```

### URL-based access control can be circumvented

This website has an unauthenticated admin panel at */admin*, but a front-end system has been configured to block external access to that path. However, the back-end application is built on a framework that supports the *X-Original-URL* header.

**Solution:**
1. Try to load */admin* and observe that you get blocked. Notice that the response is very plain, suggesting it may originate from a front-end system.
2. Send the request to Burp Repeater. Change the URL in the request line to / and add the HTTP header *X-Original-URL: /invalid*. Observe that the application returns a "not found" response. This indicates that the back-end system is processing the URL from the *X-Original-URL* header.
3. Change the value of the *X-Original-URL* header to */admin*. Observe that you can now access the admin page.
4. To delete the user *carlos*, add *?username=carlos* to the real query string, and change the *X-Original-URL* path to */admin/delete*.

### Method-based access control can be circumvented

This lab implements access controls based partly on the HTTP method of requests. You can familiarize yourself with the admin panel by logging in using the credentials administrator:admin.

**Solution:**
1. Log in using the admin credentials.
2. Browse to the admin panel, promote *carlos*, and send the HTTP request to Burp Repeater.
3. Open a private/incognito browser window, and log in with the non-admin credentials.
4. Attempt to re-promote *carlos* with the non-admin user by copying that user's session cookie into the existing Burp Repeater request, and observe that the response says "Unauthorized".
5. Change the method from *POST* to *POSTX* and observe that the response changes to "missing parameter".
6. Convert the request to use the *GET* method by right-clicking and selecting "Change request method".
7. Change the username parameter to your username and resend the request.

## Horizontal privilege escalation

Horizontal privilege escalation arises when a user is able to gain access to resources belonging to another user, instead of their own resources of that type.

 For example, if an employee should only be able to access their own employment and payroll records, but can in fact also access the records of other employees, then this is horizontal privilege escalation.

### User ID controlled by request parameter

This lab has a horizontal privilege escalation vulnerability on the user account page.

**Solution:**
1. Log in using the supplied credentials and go to your account page.
2. Note that the URL contains your username in the "id" parameter.
3. Send the request to Burp Repeater.
4. Change the "id" parameter to *carlos*.
5. Retrieve and submit the API key for *carlos*.

### User ID controlled by request parameter, with unpredictable user IDs

This lab has a horizontal privilege escalation vulnerability on the user account page, but identifies users with GUIDs.

**Solution:**
1. Find a blog post by *carlos*.
2. Click on *carlos* and observe that the URL contains his user ID. Make a note of this ID.
3. Log in using the supplied credentials and access your account page.
4. Change the "id" parameter to the saved user ID.
5. Retrieve and submit the API key.

### User ID controlled by request parameter with data leakage in redirect

This lab contains an access control vulnerability where sensitive information is leaked in the body of a redirect response.

**Solution:**
1. Log in using the supplied credentials and access your account page.
2. Send the request to Burp Repeater.
3. Change the "id" parameter to *carlos*.
4. Observe that although the response is now redirecting you to the home page, it has a body containing the API key belonging to *carlos*.
5. Submit the API key.

## Horizontal to vertical privilege escalation

Often, a horizontal privilege escalation attack can be turned into a vertical privilege escalation, by compromising a more privileged user. For example, a horizontal escalation might allow an attacker to reset or capture the password belonging to another user. If the attacker targets an administrative user and compromises their account, then they can gain administrative access and so perform vertical privilege escalation.

For example, an attacker might be able to gain access to another user's account page using the parameter tampering technique already described for horizontal privilege escalation:

```https://insecure-website.com/myaccount?id=456```

### User ID controlled by request parameter with password disclosure

This lab has user account page that contains the current user's existing password, prefilled in a masked input.

**Solution:**
1. Log in using the supplied credentials and access the user account page.
2. Change the "id" parameter in the URL to *administrator*.
3. View the response in Burp and observe that it contains the administrator's password.
4. Log in to the administrator account and delete *carlos*.

## Insecure direct object references

Insecure direct object references (IDOR) are a subcategory of access control vulnerabilities. IDOR arises when an application uses user-supplied input to access objects directly and an attacker can modify the input to obtain unauthorized access. IDOR vulnerabilities are most commonly associated with horizontal privilege escalation, but they can also arise in relation to vertical privilege escalation.

### Insecure direct object references

This lab stores user chat logs directly on the server's file system, and retrieves them using static URLs.

**Solution:**
1. Select the **Live chat** tab.
2. Send a message and then select **View transcript**.
3. Review the URL and observe that the transcripts are text files assigned a filename containing an incrementing number.
4. Change the filename to *1.txt* and review the text. Notice a password within the chat transcript.
5. Return to the main lab page and log in using the stolen credentials.

## Access control vulnerabilities in multi-step processes

This is often done when a variety of inputs or options need to be captured, or when the user needs to review and confirm details before the action is performed. For example, administrative function to update user details might involve the following steps:

1. Load form containing details for a specific user.
2. Submit changes.
3. Review the changes and confirm.

Sometimes, a web site will implement rigorous access controls over some of these steps, but ignore others. For example, suppose access controls are correctly applied to the first and second steps, but not to the third step. Effectively, the web site assumes that a user will only reach step 3 if they have already completed the first steps, which are properly controlled. Here, an attacker can gain unauthorized access to the function by skipping the first two steps and directly submitting the request for the third step with the required parameters.

### Multi-step process with no access control on one step

This lab has an admin panel with a flawed multi-step process for changing a user's role. 

**Solution:**
1. Log in using the admin credentials.
2. Browse to the admin panel, promote *carlos*, and send the confirmation HTTP request to Burp Repeater.
3. Open a private/incognito browser window, and log in with the non-admin credentials.
4. Copy the non-admin user's session cookie into the existing Repeater request, change the username to yours, and replay it.

## Referer-based access control

Some websites base access controls on the Referer header submitted in the HTTP request. The Referer header is generally added to requests by browsers to indicate the page from which a request was initiated.

For example, suppose an application robustly enforces access control over the main administrative page at /admin, but for sub-pages such as /admin/deleteUser only inspects the Referer header. If the Referer header contains the main /admin URL, then the request is allowed.

In this situation, since the Referer header can be fully controlled by an attacker, they can forge direct requests to sensitive sub-pages, supplying the required Referer header, and so gain unauthorized access.

### Referer-based access control

This lab controls access to certain admin functionality based on the Referer header.

**Solution:**
1. Log in using the admin credentials.
2. Browse to the admin panel, promote *carlos*, and send the HTTP request to Burp Repeater.
3. Open a private/incognito browser window, and log in with the non-admin credentials.
4. Browse to */admin-roles?username=carlos&action=upgrade* and observe that the request is treated as unauthorized due to the absent Referer header.
5. Copy the non-admin user's session cookie into the existing Burp Repeater request, change the username to yours, and replay it.

## Location-based access control

Some web sites enforce access controls over resources based on the user's geographical location. This can apply, for example, to banking applications or media services where state legislation or business restrictions apply. These access controls can often be circumvented by the use of web proxies, VPNs, or manipulation of client-side geolocation mechanisms.
