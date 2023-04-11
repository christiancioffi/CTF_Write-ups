# X-Men Lore (RITSEC 2023)

**Challenge category**: Web<br>
**Challenge description**: "The 90's X-Men Animated Series is better than the movies. Change my mind."<br>
**Challenge points**: 238<br>
**CTF date**: ven, 31 Mar. 2023, 16:00 UTC — dom, 02 Apr. 2023, 16:00 UTC<br>

## Context

This challenge is about a misconfigured server that unsecurely parses XML data, allowing XXE injections.

## Exploring the challenge
This is the first thing we see as soon as we access the challenge:

![Schermata_Iniziale_1](https://user-images.githubusercontent.com/66698256/229508604-a7eb4b39-4723-4a81-933b-850b454f21ce.png)

![Schermata_Iniziale_2](https://user-images.githubusercontent.com/66698256/229508636-0437331b-805d-46ac-b46d-b7139dc5b235.png)

If we click on one of the buttons (the first one, for example), we will be redirected to <code>/xmen</code>, where we can read some information about the clicked x-men character:

![Beast_1](https://user-images.githubusercontent.com/66698256/229508839-3c450744-ea36-4c67-8b59-d1a41bdadf86.png)

![Beast_2](https://user-images.githubusercontent.com/66698256/229508883-c8d4c666-dd0a-4860-96c9-3ae44825d571.png)

Clicking on the "Home" button we will be redirected to the initial page. By inspecting the *x-men* buttons something interesting can be noticed:

![Cookies](https://user-images.githubusercontent.com/66698256/229509551-f960f9b0-0f07-479e-9bf2-e525fe59b9e1.png)

When a button is clicked, a cookie called "*xmen*" is set to a base64 string and sent to the server through a GET request to <code>/xmen</code>. If we take the cookie value defined in the event handler of the "Beast" button and decode it ([[1]](#1)), we would get the following output:

![Decoding](https://user-images.githubusercontent.com/66698256/229514057-e00e2b98-a18f-4999-83dd-e888751a1536.png)

They are XML data, processed by the server to know which x-men character the user wants to receive information on. This input is then elaborated and printed within the returned page, along with some other info about the clicked x-men member. 

## Attack

If the server is not properly configured, it can processes XXE inside XML Data. So, we can inject a test XXE inside the decoded string above in order to make the server read <code>/etc/passwd</code> local file (and then print it out).

![encoding_xxe_inj](https://user-images.githubusercontent.com/66698256/229519232-23bf12f0-e9b3-4532-aaa3-8e6695a77c4e.png)

![Cookie_Set](https://user-images.githubusercontent.com/66698256/229519259-f913ed64-6673-44f0-b651-5a59d6b6f883.png)

Now we have to reload the <code>/xmen</code> page:

![Injection_executed](https://user-images.githubusercontent.com/66698256/229519399-1a44b268-9e21-4aeb-b21f-08a545636196.png)

Succesful injection! The flag is inside <code>flag</code> file. So:

![xxe_flag](https://user-images.githubusercontent.com/66698256/229520247-d33952cb-ed04-443b-9b14-c2b5e4e325f4.png)

![set_cookie_flag](https://user-images.githubusercontent.com/66698256/229520298-9dd1fb29-0c2b-4a4f-8eda-802a00965df5.png)

![Flag](https://user-images.githubusercontent.com/66698256/229520336-bb798ba5-0809-4b6e-8962-a4a0f2238f04.png)

Flag is <code>RS{XM3N_L0R3?_M0R3_L1K3_XM3N_3XT3RN4L_3NT1TY!}</code>.


## References
<a id="1">[1]</a>
https://www.base64encode.org/
