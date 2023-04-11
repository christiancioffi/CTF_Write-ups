# SQLi-2 (BucketCTF 2023)

**Challenge category**: Web<br>
**Challenge description**: "Ok I upgrade my security by preventing you from using semicolons. A stackoverflow thread told me that would work."<br>
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

We have to inject malicious data inside *Username* field (*Password* field is useless, can bet set to any value). Unlike the first challenge ([[1]](#1)) semicolons are now blocked. A simple input like <code>' OR 1=1#</code> could still cause the SQL injection attack to complete successfully.

![Injection](https://user-images.githubusercontent.com/66698256/230900875-d9610dca-72d4-487a-b47f-205aa871df01.png)

![Flag](https://user-images.githubusercontent.com/66698256/230900740-335c6e76-44d2-4386-b04b-5dacec377c1f.png)

Flag is <code>bucket{m3d1um_sq11_693f79541}</code>.

## References
<a id="1">[1]</a> 
https://github.com/H31s3n-b3rg/BucketCTF_2023/blob/main/SQLi/SQLi-1/README.md
