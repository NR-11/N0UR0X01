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
- [ ] 

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

---

> **403 bypass :**

- [ ] search in `wayback` about this subdomain you can find any important path

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
- [ ] try to change response to 200 OK
- [ ] then use match and replace to change the Response and access this page from browser 



# AUTHENTICATION BUGS



# INJECTIONS BUGS 

# CLIENT SIDE BUGS 


# API BUGS


# CMS BUGS 


# OTHER



 