<?php
    $herring = 'frequency';
    if (!isset($_COOKIE[$herring])) {
        setcookie($herring, 0, time()+600, "/"); // 86400 = 1 day
    } else {
        setcookie($herring, $_COOKIE[$herring] + 1, time()+600, "/"); // 86400 = 1 day
    }
    $cookie_name = "transmissions";
    $cookie_value = "0";
    $flag="pctf{Down_With_the_Fallen,Carnivore,Telescope,It_Has_Begun,My_Demons}";
    if (!isset($_COOKIE[$cookie_name])) {
        setcookie($cookie_name, $cookie_value, time()+600, "/"); // 86400 = 1 day
        header("Refresh:0");
    } else {
        //Set cookie 'flag' to 2 characters+index+kxkxkxkxsh
        $rand=rand(0, strlen($flag)-2);
        if ($rand==0) {
            setcookie($cookie_name, substr($flag, $rand, 2).$rand."kxkxkxkxsh", time()+600, "/");
        } elseif ($rand==strlen($flag)-2) {
            setcookie($cookie_name, "kxkxkxkxsh".substr($flag, $rand, 2).$rand, time()+600, "/");
        } else {
            setcookie($cookie_name, "kxkxkxkxsh".substr($flag, $rand, 2).$rand."kxkxkxkxsh", time()+600, "/");
        }
    }
?>

<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="utf-8"/>
    </head>
    <body style="background-image:url('./back.jpg');background-repeat:none;text-align:center;">
    <button onClick="window.location.reload()" style="position:absolute; bottom:0; left:50%;">Reload</button>
    <iframe width="560" height="315" src="https://www.youtube.com/embed/jE4przMkUqo?autoplay=1" frameborder="0" allow="autoplay; encrypted-media" allowfullscreen></iframe>
    </body>
</html>
