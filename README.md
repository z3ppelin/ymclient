ymclient v1.0
================================================
###A PHP client for Yahoo! Messenger API  
[![Build Status](https://secure.travis-ci.org/z3ppelin/ymclient.png?branch=master)](http://travis-ci.org/z3ppelin/ymclient)
[![Coverage Status](https://coveralls.io/repos/z3ppelin/ymclient/badge.png?branch=master)](https://coveralls.io/r/z3ppelin/ymclient)  

Features
--------------------
 - login
 - logout
 - avatar retreival
 - groups with contacts list retrieval
 - notifications retrieval (messages, buddy requests...)
 - messages sending
 - authorizing buddies
 - checking yahoo session & keeping it alive

Installation
-------------

1. Using [Composer](https://getcomposer.org/)  

 Add the following to your `composer.json` file located in the root directory of your project.

 ```js
 {
        "require": {
            "bogcon/ymclient": "1.0"
        }
 }
 ```  
 Then you can run the Composer install/update command from the directory containing the `composer.json` file 
 ```sh
 # download composer (skip the next command if you already have composer)
 $ curl -sS https://getcomposer.org/installer | php
 
 # install dependencies
 $ php composer.phar install
 $ php composer.phar update
 ```
2. Using GIT  

 ```sh
 git clone https://github.com/z3ppelin/ymclient.git
 ```

3. Download the ZIP archive from here [here](https://github.com/z3ppelin/ymclient/archive/master.zip)  

Usage
--------------------
```php
try {
    // initialize client
    $objYMClient = new \bogcon\ymclient\Engine('myYahooUsername', 'myYahooPass', 'app_key', 'app_secret');
    // send a quick message to a friend
    $objYMClient->logIn(\bogcon\ymclient\Engine::USER_IS_OFFLINE) // login as Invisible
        ->sendMessage('Hello...Just entered to remind you about our meeting from tomorrow. Bye, see ya.', 'myBuddyId')
        ->logOut();
    echo 'Successfully transmitted message to my friend.';
} catch (\bogcon\ymclient\Exception $objEx) {
    echo 'Something went bad: ' . $objEx->getMessage();
}
```

Yahoo API documentation
--------------------
`http://developer.yahoo.com/messenger/guide/ch02.html`

License
--------------------
`ymclient` is released under the `BSD 3-Clause License`.
You can find a copy of this license in [LICENSE.txt](LICENSE.txt).