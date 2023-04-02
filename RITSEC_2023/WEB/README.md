# Pickle Store (RITSEC 2023 - Web)

**Challenge date**: ven, 31 Mar. 2023, 16:00 UTC — dom, 02 Apr. 2023, 16:00 UTC<br>
**Challenge description**: New pickles just dropped! Check out the store.<br>
**Challenge points**: 223<br>


The server of this challenge uses the python module named *pickle*, which is used for serializing (“*Pickling*”) and de-serializing (“*Unpickling*”) Python objects' structure (see [[1]](#1)). This module is vulnerable to RCE during unpickling of class instances (objects). Classes can be definied in order to contain methods that allow to alter the default behaviour of unpickling process. One of these methods is *\_\_reduce()\_\_*. It takes no argument and shall return either a string or preferably a tuple (the returned object is often referred to as the “reduce value”).

If a string is returned, the string should be interpreted as the name of a global variable. \[...\] When a tuple is returned, it must be between two and six items long. Optional items can either be omitted, or None can be provided as their value. The semantics of each item are in order:

+A callable object that will be called to create the initial version of the object.
+A tuple of arguments for the callable object. An empty tuple must be given if the callable does not accept any argument.
## References
<a id="1">[1]</a> 
https://docs.python.org/3/library/pickle.html


