# gif (BucketCTF 2023)

**Challenge category**: Web<br>
**Challenge description**: "I made a secure php web app where I can upload all my gifs. Some people on the internet told me to run it in a docker container just to protect it from my personal files, but who cares."<br>
**Challenge points**: 272<br>
**CTF date**: ven, 07 Apr. 2023, 17:00 UTC — dom, 09 Apr. 2023, 17:00 UTC<br>

## Context

This challenge concerns an RCE caused by insufficient checks on the type of uploaded files. In particular, the file type involved is GIF. The structure of a GIF file is as follows:

![GIF_Structure](https://user-images.githubusercontent.com/66698256/231185610-1ace7bdc-907b-4eed-8dd6-4c1b220b6639.png)

As reported in [[1]](#1):

> GIF SIGNATURE<br>
The following GIF Signature identifies  the  data  following  as  a<br>
valid GIF image stream. It consists of the following six characters:<br>
G I F 8 7 a.<br>
The last three characters '87a' may be viewed as a  version  number<br>
for  this  particular  GIF  definition  and will be used in general as a<br>
reference  in  documents  regarding  GIF  that   address   any   version<br>
dependencies.
   
To specify the version of the GIF definition, each GIF file starts with a string that matches the pattern <code>GIF[0-9]{2}[a-z]</code> (for example <code>GIF87a</code>). The challenge server checks the file type based on the signature. So every file starting with a string that matches the pattern just defined is considered by the server to be a GIF file (even if its extension is not <code>gif</code>). Our goal is to upload a PHP file in order to get an RCE.


## Exploring the challenge

The web site consists of only one web page.

![Schermata_Iniziale](https://user-images.githubusercontent.com/66698256/231177553-b1772d2e-d9cf-4a70-ac79-4b367eaf35bd.png)

The data entered in this form are sent to the <code>/upload.php</code> page.

![Form](https://user-images.githubusercontent.com/66698256/231177571-2d3d9377-f1ca-4602-800c-2d7a6ad2db75.png)

We can upload any GIF file and give it any name. Let's try to upload any GIF file.

![Upload_1](https://user-images.githubusercontent.com/66698256/231177594-3f5323d6-3a71-4aaf-8935-08f9720c09b4.png)<br>

![Upload_1_Success](https://user-images.githubusercontent.com/66698256/231178375-9cc8d999-4dfd-4503-85d0-47537471c44a.png)

![Upload_1_Gif](https://user-images.githubusercontent.com/66698256/231178369-e119a287-84f0-40cb-ad01-a167e6f4bd65.png)

Let's try to upload any GIF file to an unintended location, like <code>../file.gif</code>.

![Upload_2](https://user-images.githubusercontent.com/66698256/231180213-f8db3a7c-10d0-42bb-87db-9da12c1cd3a0.png)

![Upload_2_Success](https://user-images.githubusercontent.com/66698256/231180252-233ef59c-1ad5-4764-bef9-3c2dd983095b.png)

![Upload_2_Gif](https://user-images.githubusercontent.com/66698256/231180293-df492f54-83a5-4043-84d6-a65ad3541840.png)


We can store a file wherever we want. Let's try to upload the GIF file as a PHP file.

![Upload_3](https://user-images.githubusercontent.com/66698256/231180319-50e7b4af-619a-4311-ad60-2b2f9bbd8e73.png)

![Upload_3_Success](https://user-images.githubusercontent.com/66698256/231180338-f2299540-272e-4e60-81bf-bcb7ffb7474b.png)

![Upload_3_Execution](https://user-images.githubusercontent.com/66698256/231182393-a4ba89c8-2eab-4697-b6a8-44aa46ef3e47.png)


The server run the GIF file as a PHP file (the error is due to some metadata). Let's explore the GIF file (with Block note):

![Gif_File](https://user-images.githubusercontent.com/66698256/231180401-07014406-2605-485c-9375-f52d7edaee81.png)

As described above in the *Context* section, the file starts with a signature that matches the pattern <code>GIF[0-9]{2}[a-z]</code> (<code>GIF89a</code>). You can also see the metadata that caused the error (<code>begin="ï»¿"</code>).


## Attack

To execute the attack we have to define a PHP file that starts with a string that matches the pattern <code>GIF[0-9]{2}[a-z]</code> (this string will be treated as HTML text, therefore it won't affect the exploit). We'll use <code>GIF89a</code> as the signature. File extension can be PHP, not necessarily GIF (server doesn't check file extension, only its content). So:

```php
GIF89a:<?php
echo "AAAA";
?>
```
Let's upload it and see what happens.

![Upload_exploit](https://user-images.githubusercontent.com/66698256/231181157-49bd5985-29c3-4b2b-a3cb-755a506089da.png)

![Exploit_Executed](https://user-images.githubusercontent.com/66698256/231181122-dfede20a-5288-4155-ba45-59f5b335f710.png)

We got RCE! If we could not have known the name of the folder where the files were uploaded (in this case "uploads"), we would have had to upload the exploit in the parent folder (<code>../</code>).<br>
The flag is inside <code>/flag.txt</code> file. So the file to upload should contain the following code:

```php
GIF89a:<?php
echo system("cat /flag.txt");
?>
```

Let's upload it (I don't know why it will print the flag twice).

![Upload_exploit](https://user-images.githubusercontent.com/66698256/231181157-49bd5985-29c3-4b2b-a3cb-755a506089da.png)

![Flag](https://user-images.githubusercontent.com/66698256/231184466-d5404534-4003-4d34-9a54-65ad7e4a390b.png)


Flag is <code>bucket{1_h4t3_PHP}</code>.

## References
<a id="1">[1]</a> 
https://www.w3.org/Graphics/GIF/spec-gif87.txt
