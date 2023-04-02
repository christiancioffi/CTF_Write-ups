# Pickle Store (RITSEC 2023 - Web)
### Description: "New pickles just dropped! Check out the store."

**Challenge date**: ven, 31 Mar. 2023, 16:00 UTC — dom, 02 Apr. 2023, 16:00 UTC<br>
**Challenge points**: 223<br>

## Involved Vulnerability

The server of this challenge uses the Python module named *pickle*, which is used for serializing (“*Pickling*”) and de-serializing (“*Unpickling*”) Python objects' structure (see [[1]](#1)). This module is vulnerable to RCE during unpickling of class instances (objects). Classes can be definied in order to contain methods that allow to alter the default behaviour of unpickling process. One of these methods is *\_\_reduce()\_\_*.<br>
As evidenced by [[1]](#1):<br>

>The \_\_reduce\_\_() method takes no argument and shall return either a string or preferably a tuple (the returned object is often referred to as the “reduce value”).<br>
If a string is returned, the string should be interpreted as the name of a global variable. \[...\]<br>
When a tuple is returned, it must be between two and six items long. Optional items can either be omitted, or None can be provided as their value. The semantics of each item are in order:<br> - A **callable object** that will be called to create the initial version of the object.<br> - A **tuple of arguments** for the callable object. An empty tuple must be given if the callable does not accept any argument.<br> - \[...\]

A Python function is a callable object. So, if the attacker defines a class like the one below, the server will execute the specified function with the parameters given in the tuple.
```python
class RCE:
    def __reduce__():
        return (function_name, (parameter_1,parameter_2,)) #if there is only 1 parameter: (parameter_1,)
```
## Exploring the challenge
This is the first thing the user see as soon he/she accesses the challenge:

![Pickle Store](https://user-images.githubusercontent.com/66698256/229376712-d235bbbb-0d59-4c3d-a9e0-ab0829107127.png)

If the user clicks on one of the buttons, he/she will be redirected to <code>/order</code>:

![Order executed](https://user-images.githubusercontent.com/66698256/229377403-7b7e14fd-62dd-46fd-9b15-5188b734f11d.png)

By inspecting the buttons in the initial page something interesting can be seen:

![Cookie setting](https://user-images.githubusercontent.com/66698256/229377514-b38166dd-aa58-412f-866b-9b865f722abc.png)

Every time a button is clicked a cookie named "*order*" is set. The string on which the cookie is being set is the base64 encoding of a pickled object. If we take the cookie value in the event handler of the "Sweet Pickle" button, decode it and unpickle it, we'll get the following outputs:

![Unpickling](https://user-images.githubusercontent.com/66698256/229378264-986ebdd8-36e7-48e5-9ea7-b6e36450c1db.png)

When a button is clicked, a pickled string is written into the cookie "*order*", sent to the server through a GET request to <code>/order</code>, unpickled and the value of the initial string printed into the returned page. An example:

![Pickling](https://user-images.githubusercontent.com/66698256/229378739-e7ef709d-ddd0-4338-83e7-0fce13171466.png)

![Set forged cookie](https://user-images.githubusercontent.com/66698256/229378757-81dd3bd9-0af6-4b91-8ce3-bebc4fa18b04.png)

![AAAA](https://user-images.githubusercontent.com/66698256/229378762-be51dd0c-33b0-40c2-abcf-c1b41e340fde.png)

The fact that the pickled string is ultimately printed on the returned page is of no interest to the user.

## Exploit


## References
<a id="1">[1]</a> 
https://docs.python.org/3/library/pickle.html


