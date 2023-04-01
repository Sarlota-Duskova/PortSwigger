# Client-side template injection

An attacker can exploit this by supplying a malicious template expression that launches a cross-site scripting (XSS) attack.

## AngularJS sandbox
The AngularJS sandbox is a mechanism that prevents access to potentially dangerous objects, such as window or document, in AngularJS template expressions. It also prevents access to potentially dangerous properties, such as ```__proto__```. 

The sandbox works by parsing an expression, rewriting the JavaScript, and then using various functions to test whether the rewritten code contains any dangerous objects. For example, the ```ensureSafeObject()``` function checks whether a given object references itself. This is one way to detect the ```window``` object, for example. The ```Function``` constructor is detected in roughly the same way, by checking whether the constructor property references itself.

The ```ensureSafeMemberName()``` function checks each property access of the object and, if it contains dangerous properties such as ```__proto__``` or ```__lookupGetter__```, the object will be blocked. The ```ensureSafeFunction()``` function prevents ```call()```, ```apply()```, ```bind()```, or ```constructor()``` from being called.

A sandbox escape involves tricking the sandbox into thinking the malicious expression is benign. The most well-known escape uses the modified charAt() function globally within an expression:

```'a'.constructor.prototype.charAt=[].join```

When it was initially discovered, AngularJS did not prevent this modification. The attack works by overwriting the function using the ```[].join``` method, which causes the ```charAt()``` function to return all the characters sent to it, rather than a specific single character. Due to the logic of the ```isIdent()``` function in AngularJS, it compares what it thinks is a single character against multiple characters. As single characters are always less than multiple characters, the ```isIdent()``` function always returns true, as demonstrated by the following example:

```
isIdent = function(ch) {
    return ('a' <= ch && ch <= 'z' || 'A' <= ch && ch <= 'Z' || '_' === ch || ch === '$');
}
isIdent('x9=9a9l9e9r9t9(919)')
```

Once the ```isIdent()``` function is fooled, you can inject malicious JavaScript. For example, an expression such as ```$eval('x=alert(1)')``` would be allowed because AngularJS treats every character as an identifier. Note that we need to use AngularJS's ```$eval()``` function because overwriting the ```charAt()``` function will only take effect once the sandboxed code is executed. 

## Constructing an advanced AngularJS sandbox escape

Sites that are more restrictive with which characters they allow. For example, a site may prevent you from using double or single quotes. In this situation, you need to use functions such as ```String.fromCharCode()``` to generate your characters. Although AngularJS prevents access to the ```String``` constructor within an expression, you can get round this by using the constructor property of a string instead. This obviously requires a string, so to construct an attack like this, you would need to find a way of creating a string without using single or double quotes.

In a standard sandbox escape, you would use ```$eval()``` to execute your JavaScript payload, but in the lab below, the ```$eval()``` function is undefined. Fortunately, we can use the orderBy filter instead. The typical syntax of an orderBy filter is as follows:

```[123]|orderBy:'Some string'```

Note that the | operator has a different meaning than in JavaScript. Normally, this is a bitwise OR operation, but in AngularJS it indicates a filter operation. In the code above, we are sending the array ```[123]``` on the left to the ```orderBy``` filter on the right. The colon signifies an argument to send to the filter, which in this case is a string. The ```orderBy``` filter is normally used to sort an object, but it also accepts an expression, which means we can use it to pass a payload.

### Reflected XSS with AngularJS sandbox escape without strings

This lab uses AngularJS in an unusual way where the $eval function is not available and you will be unable to use any strings in AngularJS.

To solve the lab, perform a cross-site scripting attack that escapes the sandbox and executes the alert function without using the ```$eval``` function.

**Solution:**
The exploit uses ```toString()``` to create a string without using quotes. It then gets the ```String``` prototype and overwrites the ```charAt``` function for every string. This effectively breaks the AngularJS sandbox. Next, an array is passed to the ```orderBy``` filter. We then set the argument for the filter by again using ```toString()``` to create a string and the ```String``` constructor property. Finally, we use the ```fromCharCode``` method generate our payload by converting character codes into the string ```x=alert(1)```. Because the ```charAt``` function has been overwritten, AngularJS will allow this code where normally it would not.

## Bypassing a CSP with an AngularJS sandbox escape

In order to exploit the lab, you need to think of various ways of hiding the window object from the AngularJS sandbox. One way of doing this is to use the ```array.map()``` function as follows:

```[1].map(alert)```

```map()``` accepts a function as an argument and will call it for each item in the array. This will bypass the sandbox because the reference to the ```alert()``` function is being used without explicitly referencing the window. To solve the lab, try various ways of executing ```alert()``` without triggering AngularJS's ```window``` detection.

### Reflected XSS with AngularJS sandbox escape and CSP

This lab uses CSP and AngularJS.

To solve the lab, perform a cross-site scripting attack that bypasses CSP, escapes the AngularJS sandbox, and alerts ```document.cookie```.

**Solution:**
1. Go to the exploit server and paste the following code, replacing YOUR-LAB-ID with your lab ID:

    ```
    <script>
    location='https://YOUR-LAB-ID.web-security-academy.net/?search=%3Cinput%20id=x%20ng-focus=$event.composedPath()|orderBy:%27(z=alert)(document.cookie)%27%3E#x';
    </script>
    ```

2. Click "Store" and "Deliver exploit to victim".
The exploit uses the ```ng-focus``` event in AngularJS to create a focus event that bypasses CSP. It also uses ```$event```, which is an AngularJS variable that references the event object. The ```path``` property is specific to Chrome and contains an array of elements that triggered the event. The last element in the array contains the ```window``` object.

Normally, | is a bitwise or operation in JavaScript, but in AngularJS it indicates a filter operation, in this case the ```orderBy``` filter. The colon signifies an argument that is being sent to the filter. In the argument, instead of calling the ```alert``` function directly, we assign it to the variable ```z```. The function will only be called when the ```orderBy``` operation reaches the ```window``` object in the ```$event.path``` array. This means it can be called in the scope of the window without an explicit reference to the ```window``` object, effectively bypassing AngularJS's window check.