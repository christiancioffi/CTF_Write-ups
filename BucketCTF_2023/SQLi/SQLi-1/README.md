# SQLi-1 (BucketCTF 2023)

**Challenge category**: Web<br>
**Challenge description**: "This is my first time using SQL. Its such a great and simple tool."<br>
**Challenge points**: 200<br>
**CTF date**: ven, 07 Apr. 2023, 17:00 UTC — dom, 09 Apr. 2023, 17:00 UTC<br>

## Context

This challenge is about a simple SQL Injection.


## Exploring the challenge

The web site consists of only one web page.

![Schermata_Iniziale](https://user-images.githubusercontent.com/66698256/230898644-29dea83c-95ed-4a68-9412-306e6daa7c4b.png)

The data entered in this form are sent to the <code>/login</code> endpoint.

![Form](https://user-images.githubusercontent.com/66698256/230898833-f8860ab6-7a15-497f-b0e3-91b9624e601d.png)

## Attack

We have to inject malicious data inside *Username* field (*Password* field is useless, can bet set to any value). A simple input like <code>' OR 1=1;#</code> will cause the SQL injection attack to complete successfully.

![Injection](https://user-images.githubusercontent.com/66698256/230899156-4caeabc0-b3b4-411e-9e97-0b09cfbee86f.png)

![Flag](https://user-images.githubusercontent.com/66698256/230899170-aba370dd-f56a-4753-9d70-660c50aa15d6.png)

Flag is <code>bucket{s1mp13_sq11_ed0176a}</code>.
