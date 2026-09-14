"""SAST (Static Application Security Testing (analysis of the application's own source code) 
via AST parsing (Abstract Syntax Tree) it reads the code the way python itself understands it - as structure, not text. Every piece of code becomes a "node" in a tree"""

# For every rule, there is one function assign to the main class (findings)
#Import findings file from main class 
from scanner.findings import Finding
#AST module for Abstract Syntax Tree functionality
import ast

#Variables where harcdoed fallback inside os.getenv ()/ os.environ.get() is considred unsafe, since each ends up feeding a security-sensitive setting. 
#Ad new variable names here if a similar risk is found elsewhere. 
ENV_FALLBACK_WATCHLIST = {
    "SECRET_KEY": {
        "rule_id": "SEC-MISCONFIG-SECRET-KEY-FALLBACK",
        "attack_type_exposure" : "Session/Cookie Forgery",
    },
    "_ALLOWED_HOSTS": {
        "rule_id": "SEC-MISCONFIG-ALLOWED-HOSTS-FALLBACK",
        "attack_type_exposure": "Host Header Injection",
    },
}

#Parameter tree as type ast.AST
#Parameter filepath as type str
def check_security_misconfig(tree: ast.AST, filepath: str) -> list [Finding]: #-> this function will return a list of finding objects
    findings = [] #Empty list which the function will fill up as it walks the three and returns at the end. 

    # ---RULE 4 SET UP:collects every variable name assigned anywhere in the file - needed
    #for rule 4, which can only be checked after seeing the whole file
    assigned_names = set()


    #ast.walk(tree) visit every single node in the whole three. Every function, imports, if-statements, etc.
    #The "node" variable becomes each of thise per iteration is a loop for every node in the code.
    for node in ast.walk(tree):
        #isistance = "Guard clause": isinstance(thing, SomeType) asks a yes/no question: "is thing of type SomeType?
        #It will return true or false
        #Skip anything that isnt an Assign node (x=y), so the rest of this loop can safely assume "node" is an assignment without extra nesting
        if not isinstance(node, ast.Assign):
            continue
        
        #node.targets is a list, not a single value
        for target in node.targets:
        #The target are only plain variable names node types (ast.Name like DEBUG)
            if not isinstance(target, ast.Name):
                continue

            # Record every assigned name for Rule 4 presente
            assigned_names.add(target.id)

            #--- Environment-variable hardcoded fallback check (Applicable to rule 1 & 2)---
            #Attack type covered: a variable is correctly loaded from an environment variable but hardcoded, unsafe literal is provided as the fallback value -
            #meaning  the "safe" pattern silently degrades if that env var is ever missing. Applies to any variable in ENV_FALLBACK_WATCHLIST
            if target.id in ENV_FALLBACK_WATCHLIST:
                if isinstance (node.value, ast.Call):
                    if isinstance (node.value.func, ast.Attribute) and node.value.func.attr in ("getenv", "get"):
                        if len (node.value.args) >= 2:
                            fallback_arg = node.value.args [1]
                            
                            #Only flag if the fallback is a real (non-empty) string literal. 
                            if isinstance (fallback_arg, ast.Constant) and isinstance (fallback_arg.value, str) and fallback_arg.value:
                                watchlist_entry = ENV_FALLBACK_WATCHLIST[target.id]
                                findings.append (Finding(
                                     rule_id= watchlist_entry["rule_id"],
                                     severity="Critical",
                                     attack_type_exposure=watchlist_entry["attack_type_exposure"],
                                     file_path=filepath,
                                     line=node.lineno,
                                     message=f"{target.id} is loaded from an environment variable, but a hardcoded fallback value is provided. If the environment variable is ever unset, the app will sillently run with this fallback value, which is visible in source control.", 
                                     standard_ref="OWASP Top 10:2025 A02 – Security Misconfiguration",
                                     ))

                                 
            #---------TIER 1 START : Presence check (e.g. SECURE_SSL_REDIRECT, DEBUG, etc)----
            #judged from assignments alone — either one assignment's own value (flat literal), or whether a name was assigned anywhere at all (presence). 
            # No function calls, no argument inspection, no structural walking.

            # ---RULE 1 Attack type Security misconfiguration — DEBUG ----
            # Attack type covered: information disclosure via debug error pages —leaking stack traces and internal app structure to any visitor.

            # DEBUG is a setting in settings.py that controls how Django behaves when something goes wrong. It was two different modes. 
            # DEBUG = TRUE When an error happens, instead of a plain "Something went wrong" page, Django shows a detailed, interactive error page right in the browser
            # DEBUG = False Errors just show a plain, generic error page with none of that detail, because a live app shouldn't hand debugging information to random visitors.

            if target.id == "DEBUG":
                if isinstance (node.value, ast.Constant) and node.value.value is True: #if DEBUG = True defined on settings.py. When an error happens, it will display the traceback error details. 
                    #Revealing revealing CMS structure and DB schema to any visitor.

                    findings.append(Finding( #Append finding to main class findings
                        #Details from class (according also to rules matrix documentation on excel)
                        rule_id="SEC-MISCONFIG-DEBUG",
                        severity ="Critical",
                        attack_type_exposure="Stack Trace Exposure",
                        file_path=filepath, 
                        line=node.lineno,
                        message="DEBUG is set to True. In production this exposes detailed error tracebacks — including internal file paths and code structure — to any visitor.",
                        standard_ref= "OWASP Top 10:2025 A02 – Security Misconfiguration", #Standard name from OWASP matrix documentation
                    ))

            # --- RULE 2 Attack type Security misconfiguration — SECRET_KEY ---
            # Attack type covered: cryptographic key exposure — enabling session/token forgery.

            # Notes:
            # SECRET_KEY is used internally by Django to cryptographically sign things —session cookies, password-reset tokens, CSRF tokens. If an attacker learns
            # this value, they can forge any of those (e.g. a fake "logged in as admin" session) without ever needing a real password.
            
            # This rule flags SECRET_KEY whenever it's hardcoded directly in the source —
            # unsafe because it's committed to version control and can't differ between
            # environments. The safe pattern loads it from an environment variable at
            # runtime instead (e.g. os.environ.get("SECRET_KEY")), which this rule ignores.
            
            
            if target.id == "SECRET_KEY":
                #Shape A: harcoded directly as a string (SECRET_KEY = "abcd123")
                # Constant = a literal value written directly in the code.
                # isinstance(..., str) narrows it to strings specifically, since constant also covers True/False/numbers.
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    findings.append(Finding(
                         rule_id="SEC-MISCONFIG-SECRET-KEY",
                         severity="Critical",
                         attack_type_exposure="Session/Cookie Forgery",
                         file_path=filepath,
                         line=node.lineno,
                         message="SECRET_KEY is a hardcoded string literal instead of being loaded from the environment.",
                         standard_ref="OWASP Top 10:2025 A02 – Security Misconfiguration",  # Standard name from OWASP matrix documentation
                     ))
              
            # ---RULE 3 Attack type Security misconfiguration — ALLOWED_HOST ---
            # Attack type covered: Host header injection — allowing any host to connect.
            if target.id == "ALLOWED_HOSTS":
                # This condition only runs if the value is a list literal at all,
                # e.g. [] or ['*', 'example.com'] — not a variable or function call.
                if isinstance(node.value, ast.List):
                    # Condition 1 — is the list completely empty?
                    # len(node.value.elts) counts how many items are inside the list.
                    # If it's 0, ALLOWED_HOSTS was left blank.
                    if len(node.value.elts) == 0:
                        findings.append(Finding(
                            rule_id="SEC-MISCONFIG-ALLOWED-HOSTS-EMPTY",
                            severity="Critical",
                            attack_type_exposure="Host Header Injection",
                            file_path=filepath,
                            line=node.lineno,
                            message="ALLOWED_HOSTS is empty.",
                            standard_ref="OWASP Top 10:2025 A02 – Security Misconfiguration",
                        ))
                    else:
                        # Condition 2 — the list has items, so check each one individually
                        # to see if the wildcard '*' is hiding among them.
                        for elt in node.value.elts:
                            # isinstance(elt, ast.Constant) confirms this item is a plain
                            # literal value (like a string), not a variable or expression.
                            # elt.value == "*" then checks if that literal is specifically
                            # the wildcard character.
                            if isinstance(elt, ast.Constant) and elt.value == "*":
                                findings.append(Finding(
                                    rule_id="SEC-MISCONFIG-ALLOWED-HOSTS-WILDCARD",
                                    severity="Critical",
                                    attack_type_exposure="Host Header Injection",
                                    file_path=filepath,
                                    line=node.lineno,
                                    message="ALLOWED_HOSTS contains '*', allowing any host.",
                                    standard_ref="OWASP Top 10:2025 A02 – Security Misconfiguration",
                                ))

                        #Condition 3 - dynamic ALLOWED_HOSTS dynamic construction check
                elif isinstance (node.value, ast.ListComp):
                    findings.append(Finding(
                         rule_id="SEC-MISCONFIG-ALLOWED-HOSTS-DYNAMIC",
                         severity="Medium",
                         attack_type_exposure="Host Header Injection",
                         file_path=filepath,
                         line=node.lineno,
                         message=(
                             "ALLOWED_HOSTS is built dynamically (e.g. via a list comprehension "
                             "over an environment variable) rather than as a plain list literal. "
                             "This rule cannot verify what value it actually resolves to without "
                             "running the code, so a dangerous default hidden inside the "
                             "expression — e.g. os.getenv('ALLOWED_HOSTS', '*') falling back to "
                             "a wildcard if the environment variable is unset — would go "
                             "completely undetected. Manually confirm the fallback value used "
                             "here is a safe, explicit domain list, not an empty string or '*'."
                        ),
                        standard_ref="OWASP Top 10:2025 A02 – Security Misconfiguration",
        ))
    
                                     
# ---RULE 4: Security misconfiguration - missing SSL/HSTS ---
    #Only applies to settings.py 
    # Presence check only (Django doesn't enable these by default, and the 
    # value could come from an env var I can't verify statically (needs manual review)
    #Attack type covered: Man in the middle attack (MITM) through SSL-Stripping, attack that
    #forces a target's browser to downgrade from HTTPS (encrypted) to HTTP (unencrypted)
    #traffic and session cookies (e.g. CMS admin login) can be intercepted

    #Django does not enable this HTTPS enforcement by default - both settings must be explicitly added.
    #this is a PRESENCE check, not a value check:
    #we're only asking "were these names ever assigned at all?", not what
    #they equal, since the actual value could come from an env var or a
    #conditional that can't be verified statically
    if filepath.endswith("settings.py"):
        missing_ssl_keys = []
        if "SECURE_SSL_REDIRECT" not in assigned_names:
            missing_ssl_keys.append("SECURE_SSL_REDIRECT")
        if "SECURE_HSTS_SECONDS" not in assigned_names:
            missing_ssl_keys.append("SECURE_HSTS_SECONDS")

        if missing_ssl_keys:
            findings.append(Finding(
                rule_id="SEC-MISCONFIG-SSL-HSTS-MISSING",
                severity="Critical",
                attack_type_exposure="SSL Stripping (Man-in-the-Middle)",
                file_path=filepath,
                #I put 1 here on purpose. It's not a real line number — this rule is about something missing, and missing things don't have a line
                line=1,
                message=(
                    f"Missing HTTPS enforcement settings(s): {', '.join(missing_ssl_keys)}. "
                    "Without these, traffic and session cookies (e.g. CMS admin login) can be "
                    "intercepted via SSL stripping / man-in-the-middle attacks. Add "
                    "SECURE_SSL_REDIRECT = True and SECURE_HSTS_SECONDS = 31536000."
                ),
                standard_ref="OWASP Top 10:2025 A02 – Security Misconfiguration",
            ))
    return findings 

#---RULE 5 SEC-MISCONFIG-HARDCODED-SECRET---
#Variable names that typically hold secrets. If any of these is assigned
#a hardcoded string instead of being kept secret.
SECRET_NAME_PATTERNS = ("SECRET", "PASSWORD", "API_KEY", "TOKEN", "PRIVATE_KEY")

def check_hardcoded_secrets(tree, filepath):
    findings = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue
            #Check if the variable name looks secret-like(SECRET_KEY, API_KEY, DB_PASSWORD, etc.)
            name_upper = target.id.upper()
            if not any(pattern in name_upper for pattern in SECRET_NAME_PATTERNS):
                continue
            #Only flag if the VALUE is a hardcoded string literal — if it's
            #.env that's the safe pattern already covered by ENV_FALLBACK_WATCHLIST.
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str) and node.value.value:
                findings.append(Finding(
                    rule_id="SEC-MISCONFIG-HARDCODED-SECRET",
                    severity="High",
                    attack_type_exposure="Credential Exposure",
                    file_path=filepath,
                    line=node.lineno,
                    message=f"{target.id} is a hardcoded secret-like value in source code. Anyone with repo access can read it. Move it to .env and load it via os.environ.get('{target.id}').",
                    standard_ref="OWASP Top 10:2025 A02 – Security Misconfiguration",
                ))

    return findings

                #---TIER 2 START ----

#---RULE 6 DANGEROUS CALLS - eval() / exec () ----
#looks for dangerous call names eval() / exec ()that the attacker can use as 
#and pass it as code, if that string ever comes from user input the attacker can run their own code on our server 
#(Read files, access the database, anything python can do)
DANGEROUS_CALL_NAMES = ("eval", "exec")

def check_unsafe_eval_exec(tree, filepath):
    findings = []
    for node in ast.walk(tree):
        #Only care about function CALL nodes — e.g. eval(x), not just the word eval
        if not isinstance(node, ast.Call):
            continue

        #The function being called must be a plain name (not something.eval())
        if not isinstance(node.func, ast.Name):
            continue

        #Is this call to eval or exec specifically?
        if node.func.id in DANGEROUS_CALL_NAMES:
            findings.append(Finding(
                rule_id="SEC-UNSAFE-EVAL-EXEC",
                severity="Critical",
                attack_type_exposure="Arbitrary Code Execution",
                file_path=filepath,
                line=node.lineno,
                message=f"Call to {node.func.id}() found. If any part of its input comes from user data, this allows arbitrary code execution. Avoid eval/exec entirely, or use ast.literal_eval() for safe data parsing.",
                standard_ref="OWASP Top 10:2025 A03 – Injection",
            ))

    return findings

# ---RULE 7 DANGEROUS_DESERIALIZE_CALLS pickle.loads ---

#Looks for pickle.loads() calls — pickle doesn't just read data, it can
#reconstruct and RUN arbitrary Python objects from the bytes it's given.
#If the argument comes from outside the code (request data, cache, file
#upload) instead of a hardcoded literal, an attacker can craft a payload
#that executes their own code the moment it's loaded.
DANGEROUS_DESERIALIZE_CALLS = ("loads", "load")

def check_insecure_deserialization(tree, filepath):
    findings = []
    for node in ast.walk(tree):
        #Only care about function CALL nodes
        if not isinstance(node, ast.Call):
            continue

        #We're looking for pickle.loads(...) or pickle.load(...) —
        #that's an Attribute access (pickle.something), not a plain Name
        if not isinstance(node.func, ast.Attribute):
            continue

        #Confirm the object being called on is literally named "pickle"
        #(pickle.loads), and the method is loads/load specifically
        if not isinstance(node.func.value, ast.Name):
            continue
        if node.func.value.id != "pickle":
            continue
        if node.func.attr not in DANGEROUS_DESERIALIZE_CALLS:
            continue

        #No arguments at all — nothing to check, skip
        if not node.args:
            continue

        first_arg = node.args[0]

        #LIGHT TAINT CHECK: is the argument a hardcoded literal (safe,
        #e.g. pickle.loads(b"...")) or anything else (a variable, a
        #function call, request.body, etc — unknown origin, flag it)?
        if isinstance(first_arg, ast.Constant):
            continue  #True Negative don't create an issue, literal data, not attacker-controlled

        findings.append(Finding(
            rule_id="SEC-INSECURE-DESERIALIZATION-PICKLE",
            severity="Medium",
            attack_type_exposure="Remote Code Execution (Insecure Deserialization)",
            file_path=filepath,
            line=node.lineno,
            message=f"pickle.{node.func.attr}() is called with a non-literal argument. If this data crosses a trust boundary (request body, cache, file upload), a crafted payload can achieve remote code execution. Replace pickle with json for any data from outside the code.",
            standard_ref="OWASP Top 10:2025 A08 – Software or Data Integrity Failures",
        ))

    return findings

#---RULE 8 WEAK HASHING - hashlib.md5() / hashlib.sha1() ----
#Why these 2 on specific?  these 2 hashes techniques broken & depreceated by OWASP 
# algorithms still built intoy python standard library,and which are still commonly used

WEAK_HASH_ALGORITHMS = ("md5", "sha1")

def check_weak_hashing(tree, filepath):
    findings = []
    for node in ast.walk(tree):
        #Only care about function CALL nodes
        if not isinstance(node, ast.Call):
            continue

        #looking for hashlib.md5(...) or hashlib.sha1(...) —
        #that's an Attribute access (hashlib.something), not a plain Name
        if not isinstance(node.func, ast.Attribute):
            continue

        #Comfirm the object being called on is named "hashlib"
        if not isinstance(node.func.value, ast.Name):
            continue
        if node.func.value.id != "hashlib":
            continue

        #Is this call to md5 or sha1 specifically?
        if node.func.attr in WEAK_HASH_ALGORITHMS:
            findings.append(Finding(
                rule_id="SEC-WEAK-HASHING-ALGORITHM",
                severity="Medium",
                attack_type_exposure="Cryptographic Weakness",
                file_path=filepath,
                line=node.lineno,
                message=f"hashlib.{node.func.attr}() is a broken hashing algorithm — collisions can be crafted deliberately. Use hashlib.sha256() or stronger. For passwords specifically, use Django's built-in make_password() (Argon2/PBKDF2) instead of manual hashing.",
                standard_ref="OWASP Top 10:2025 A04 – Cryptographic Failures",
            ))

    return findings

#---RULE 9 UNSAFE IMAGE UPLOAD - Image.open() on request.FILES ---

#Looks for image.open() called directly on request.FILES with no validation first

#A crafted image (image modified by an attacher that can be visualized normally but the internal gygabites structure is modified)
# when decode it into gygabites of pixel data (decompression bomb) or trigger a known 
# CVE- (common vulnerability exposure in third libraries used in python) 
# the attacker con exploit the attack techniques exhausting server memory(CPU) 

def check_unsafe_image_upload(tree, filepath):
    findings = []
    for node in ast.walk(tree):
        #Only care about function CALL nodes
        if not isinstance(node, ast.Call):
            continue

        #Looking for Image.open(...) — that's an Attribute access
        if not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr != "open":
            continue
        if not isinstance(node.func.value, ast.Name):
            continue
        if node.func.value.id != "Image":
            continue

        #No arguments — nothing to check
        if not node.args:
            continue

        first_arg = node.args[0]

        #Convert the argument to source-like text so I can check if it
        #mentions "request.FILES" — a simple text check, not full taint
        #tracing, but enough to catch the direct/unvalidated case.
        arg_text = ast.dump(first_arg)
        if "FILES" not in arg_text:
            continue  #not an upload — not what this rule cares about

        findings.append(Finding(
            rule_id="SEC-UNSAFE-IMAGE-UPLOAD",
            severity="Medium",
            attack_type_exposure="Denial of Service (Decompression Bomb)",
            file_path=filepath,
            line=node.lineno,
            message="Image.open() is called directly on request.FILES with no visible validation. A crafted image can trigger a decompression bomb or exploit a known Pillow vulnerability. Validate file size, MIME type, and dimensions before processing, and set Image.MAX_IMAGE_PIXELS.",
            standard_ref="OWASP Top 10:2025 A02 – Security Misconfiguration / A05 – Injection",
        ))

    return findings

#---TIER 2/3 - call-pattern + string content check (does the regex literal contain a nested quantifier?)---

#---RULE 10 ReDoS - UNSAFE REGEX PATTERNS ----

# REGEX definition = python regular expression is a pattern-matching lenguage
#SHAPES of text, not exact fixed strings  

#Looks for re.compile()/re.match()/re.search() calls where the pattern
#contains a NESTED QUANTIFIER shape — e.g. (a+)+ or (a*)*. These cause
#catastrophic backtracking: a CRAFTED input string (deliberately built
#by an attacker) can make matching time explode exponentially, freezing
#a worker and exhausting the whole worker pool (DoS).
#Pool of workers - server application server available to handle requests

#Note: the danger is in the PATTERN (code I wrote), not the runtime
#input — this rule only sees the pattern, since that's what's in source.

import re as re_module  #aliased so it doesn't collide with the "re" i'm scanning FOR

REGEX_CALL_NAMES = ("compile", "match", "search", "fullmatch")

#A lightweight, deliberately simple detector for the classic nested-
#quantifier shape: a group containing a quantifier, itself followed by
#another quantifier — e.g. (a+)+, (a*)*, (a|aa)+. Not a full analysis,
#just a pattern match over the regex text itself.
NESTED_QUANTIFIER_SHAPE = re_module.compile(r"\([^()]*[+*][^()]*\)[+*]")

def check_redos_unsafe_regex(tree, filepath):
    findings = []
    for node in ast.walk(tree):
        #Only care about function CALL nodes
        if not isinstance(node, ast.Call):
            continue

        #Looking for re.compile(...) / re.match(...) / re.search(...) /
        #re.fullmatch(...) — Attribute access, object literally named "re"
        if not isinstance(node.func, ast.Attribute):
            continue
        if not isinstance(node.func.value, ast.Name):
            continue
        if node.func.value.id != "re":
            continue
        if node.func.attr not in REGEX_CALL_NAMES:
            continue

        #No arguments — nothing to check
        if not node.args:
            continue

        first_arg = node.args[0]

        #Only useful if the pattern is a hardcoded string literal — if
        #it's a variable, I can't see its actual text at scan time.
        if not isinstance(first_arg, ast.Constant) or not isinstance(first_arg.value, str):
            continue

        pattern_text = first_arg.value

        #Does the pattern's own text contain the dangerous nested-
        #quantifier shape?
        if NESTED_QUANTIFIER_SHAPE.search(pattern_text):
            findings.append(Finding(
                rule_id="SEC-REDOS-UNSAFE-REGEX",
                severity="Medium",
                attack_type_exposure="CPU Exhaustion (ReDoS)",
                file_path=filepath,
                line=node.lineno,
                message=f"re.{node.func.attr}() uses a pattern with nested quantifiers, vulnerable to catastrophic backtracking. A crafted input string can freeze this worker for minutes, and repeated requests can exhaust the whole worker pool (denial of service). Avoid nested quantifiers; use bounded quantifiers with a fixed max length.",
                standard_ref="CWE-1333 – Inefficient Regular Expression Complexity",
            ))

    return findings

#---RULE 11 RESOURCE STARVATION - MISSING TIMEOUTS / UNCLOSED RESOURCES ----

#Two related checks: (1) outbound HTTP calls with no timeout= can hang
#forever if the remote server never responds, tying up a worker
#indefinitely; (2) file handles/DB cursors/sockets opened without a
#"with" block can leak if an exception happens before .close() runs.
#Both slowly exhaust a limited resource pool (workers, file handles,
#DB connections) under repeated/parallel requests — same DoS family
#as ReDoS, but starving CONNECTIONS/WORKERS instead of CPU.

HTTP_CALL_METHODS = ("get", "post", "put", "delete", "patch", "head")

def check_missing_timeout(tree, filepath):
    findings = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        #Looking for requests.get(...) / requests.post(...) etc —
        #Attribute access, object literally named "requests"
        if not isinstance(node.func, ast.Attribute):
            continue
        if not isinstance(node.func.value, ast.Name):
            continue
        if node.func.value.id != "requests":
            continue
        if node.func.attr not in HTTP_CALL_METHODS:
            continue

        #Check the KEYWORD arguments for timeout= — node.keywords is a
        #list of ast.keyword nodes, each with a .arg (the name) and
        #.value (what it's set to). I just need to know if "timeout"
        #was passed at all — not checking what value it's set to.
        has_timeout = any(kw.arg == "timeout" for kw in node.keywords)

        if not has_timeout:
            findings.append(Finding(
                rule_id="SEC-MISSING-TIMEOUT",
                severity="High",
                attack_type_exposure="Worker/Connection Pool Exhaustion",
                file_path=filepath,
                line=node.lineno,
                message=f"requests.{node.func.attr}() is called with no timeout= argument. If the remote server never responds, this call hangs forever, tying up a worker indefinitely. Repeated hangs exhaust the whole worker pool. Always pass an explicit timeout=.",
                standard_ref="CWE-400 – Uncontrolled Resource Consumption",
            ))

    return findings

#---RULE 12 SILENT FAIL-OPEN -BARE/ EMTPY EXCEPT ---

#Silent Fail-Open — an error is caught but silently ignored (except: pass), so the code continues as if nothing went wrong.
# If this happens during a permission check or validation, the request proceeds as if it succeeded — an attacker who triggers the error gets treated as authorized by accident.

#New AST node type: ast.ExceptHandler

def check_silent_fail_open(tree, filepath):
    findings = []
    for node in ast.walk(tree):
        #Looking for an "except ...:" block specifically 
        if not isinstance(node, ast.ExceptHandler):
            continue

        #Is this a bare "except:" with no error type at all?
        is_bare_except = node.type is None

        #Or does it say "except Exception:" — still catches almost
        #everything, just slightly less extreme than fully bare
        is_broad_exception = (
            isinstance(node.type, ast.Name) and node.type.id == "Exception"
        )

        #If it catches a SPECIFIC error type instead, skip it — that's fine
        if not (is_bare_except or is_broad_exception):
            continue

        #Now check what's INSIDE the except block — is it just "pass",
        #meaning it does nothing at all with the error?
        body_is_noop = (
            len(node.body) == 1
            and isinstance(node.body[0], ast.Pass)
        )

        #If it does something (logs, re-raises, returns an error), skip it
        if not body_is_noop:
            continue

        findings.append(Finding(
            rule_id="SEC-SILENT-FAIL-OPEN",
            severity="Medium",
            attack_type_exposure="Silent Fail-Open",
            file_path=filepath,
            line=node.lineno,
            message="This except block silently swallows the error with no logging or handling. If this wraps a permission check, validation, or moderation step, the request continues as if it succeeded even though it failed. Catch specific exception types, log the error, and fail closed (deny/return an error).",
            standard_ref="OWASP Top 10:2025 A10 – Mishandling of Exceptional Conditions",
        ))

    return findings

#---RULE 13 SQL INJECTION via String Concatenation ---
#SQL Injection via String Concatenation (most common form) — a code-
#level flaw where a query string is built by GLUING (concatenation) user input directly
#into SQL text, instead of using a parameterized placeholder.

#Example: login bypass
#  Intended (NOT parameterized):
#    SELECT * FROM users WHERE username='USER_INPUT' AND password='PASS';
#  Attacker enters into username: admin' --
#  Because the string was built via concatenation in OUR CODE (not the
#  database), the final string sent becomes:
#    SELECT * FROM users WHERE username='admin' --' AND password='...';
#  Everything after -- is a SQL comment, so the password check never
#  runs — attacker logs in as admin with no valid password.
#  (Login bypass is just ONE outcome — the same flaw can also read,
#  modify, or delete data across the whole database.)

#Looks for cursor.execute() calls where the query string is BUILT at
#runtime via string concatenation (+) or an f-string, instead of being
#a safe literal with placeholders. If any part of that built string
#comes from user input, an attacker can inject their own SQL.

#Prevention: parameterized queries (%s placeholders + a separate params
#list) — this is exactly what this rule checks FOR the absence of.

def check_sql_injection(tree, filepath):
    findings = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        #Looking for cursor.execute(...) — Attribute access ending in
        #"execute"(METHOD)
        if not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr != "execute":
            continue

        if not node.args:
            continue

        query_arg = node.args[0]

        #DANGER SHAPE 1: an f-string. In the AST, f-strings become a
        #JoinedStr node — a mix of literal text pieces AND embedded
        #expressions (the {variable} parts). Any JoinedStr means a
        #variable got glued directly into the query text.
        is_fstring = isinstance(query_arg, ast.JoinedStr)

        #DANGER SHAPE 2: string concatenation or % formatting, e.g.
        #"SELECT * WHERE id=" + tip_id, or "...%s" % tip_id. In the
        #AST, both + and % both are the same danger shape here.
        is_binop_built = isinstance(query_arg, ast.BinOp)

        if not (is_fstring or is_binop_built):
            continue  #plain string literal or %s-placeholder call — safe, skip

        findings.append(Finding(
            rule_id="SEC-SQL-INJECTION",
            severity="Critical",
            attack_type_exposure="SQL Injection",
            file_path=filepath,
            line=node.lineno,
            message="cursor.execute() is called with a query string built via f-string or concatenation instead of a parameterised placeholder. If any part of this string comes from user input, an attacker can inject arbitrary SQL, risking full database exfiltration or authentication bypass. Use %s placeholders with a separate params list instead.",
            standard_ref="OWASP Top 10:2025 A05 – Injection",
        ))

    return findings

#---RULE 14 SSRF - USER-CONTROLLED URL FETCH ----

#SSRF (Server-Side Request Forgery): the SERVER fetches a URL on the
#user's behalf. If that URL isn't validated, an attacker can point it
#at internal-only resources instead of the public internet — localhost,
#your database's internal port, or cloud metadata endpoints
#(169.254.169.254, which can leak cloud credentials). The request comes
#FROM your server, so it can reach things the attacker never could
#directly.

#Looks for requests.get()/post() (or urlopen) calls where the URL
#argument traces back to request data (request.data, request.GET,
#request.POST, request.json) — a light taint trace, not full tracking:
#we check if "request." text appears in the argument, not where it
#originally came from further back.

HTTP_FETCH_METHODS = ("get", "post", "put", "delete", "patch")

def check_ssrf(tree, filepath):
    findings = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        #Looking for requests.get(...) / requests.post(...) etc —
        #same call shape as check_missing_timeout, different concern
        if not isinstance(node.func, ast.Attribute):
            continue
        if not isinstance(node.func.value, ast.Name):
            continue
        if node.func.value.id != "requests":
            continue
        if node.func.attr not in HTTP_FETCH_METHODS:
            continue

        if not node.args:
            continue

        url_arg = node.args[0]

        #LIGHT TAINT CHECK: does the URL argument's own text mention
        #"request" anywhere in it? Using ast.dump() to get a text
        #representation of the argument, same technique as the image
        #upload rule — not full data-flow tracing, just checking if
        #request data is being used directly as the URL.
        arg_text = ast.dump(url_arg)
        if "request" not in arg_text.lower():
            continue  #URL isn't from request data — not what this rule flags

        findings.append(Finding(
            rule_id="SEC-SSRF-USER-CONTROLLED-URL",
            severity="High",
            attack_type_exposure="Server-Side Request Forgery (SSRF)",
            file_path=filepath,
            line=node.lineno,
            message=f"requests.{node.func.attr}() is called with a URL sourced from request data, with no visible validation. An attacker can point this at internal-only services (localhost, database ports, cloud metadata endpoints) instead of the public internet. Validate the URL against an explicit allow-list of hosts/schemes before fetching.",
            standard_ref="OWASP Top 10:2025 A01 – Broken Access Control",
        ))

    return findings

#---RULE 15 CROSS-SITE-REQUEST-FORGERY (CSRF) ---
#Two related but distinct checks CSRF_EXEPT/ PERMISSIVE CORS matching the project stack

#(django-cors-headers + vanilla JS frontend calling the Django API):
#
#1) @csrf_exempt disables Django's built-in CSRF protection on a view.
#   CSRF: a malicious site tricks a logged-in user's browser into
#   silently sending a request to OUR site using their real session —
#   e.g. forging a tip submission or admin action without them knowing.
#
#2) CORS_ALLOW_ALL_ORIGINS = True (or a "*" in CORS_ALLOWED_ORIGINS)
#   lets ANY website read responses from our API via cross-origin
#   requests — a different problem: not forcing an action, but letting
#   any site READ our API's data.

def check_csrf_exempt(tree, filepath):
    """Tier 3: decorator check — is @csrf_exempt applied to a view?"""
    findings = []
    for node in ast.walk(tree):
        #Decorators only exist on function/class definitions
        if not isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            continue

        #decorator_list is a list of the @decorator expressions above
        #this function/class — could be @csrf_exempt, @login_required,
        #multiple stacked decorators, etc.
        for decorator in node.decorator_list:
            #A plain decorator name looks like: @csrf_exempt
            if isinstance(decorator, ast.Name) and decorator.id == "csrf_exempt":
                findings.append(Finding(
                    rule_id="SEC-CSRF-EXEMPT",
                    severity="High",
                    attack_type_exposure="Cross-Site Request Forgery (CSRF)",
                    file_path=filepath,
                    line=node.lineno,
                    message=f"@csrf_exempt disables CSRF protection on '{node.name}'. A malicious site could trick a logged-in user's browser into silently submitting a forged request. Remove this decorator unless justified with a code comment explaining why it's safe here.",
                    standard_ref="OWASP Top 10:2025 A01 – Broken Access Control",
                ))

    return findings


def check_permissive_cors(tree, filepath):
    """Tier 1: settings check — is CORS wide open?"""
    findings = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue

        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue

            #Case A: CORS_ALLOW_ALL_ORIGINS = True — flat literal check,
            #same shape as DEBUG rule
            if target.id == "CORS_ALLOW_ALL_ORIGINS":
                if isinstance(node.value, ast.Constant) and node.value.value is True:
                    findings.append(Finding(
                        rule_id="SEC-PERMISSIVE-CORS",
                        severity="High",
                        attack_type_exposure="Permissive CORS (Any-Origin Access)",
                        file_path=filepath,
                        line=node.lineno,
                        message="CORS_ALLOW_ALL_ORIGINS is set to True. Any website on the internet can make cross-origin requests to this API and read the response. Set an explicit CORS_ALLOWED_ORIGINS list instead.",
                        standard_ref="OWASP Top 10:2025 A02 – Security Misconfiguration",
                    ))

            #Case B: CORS_ALLOWED_ORIGINS contains "*" — same wildcard
            #check shape as ALLOWED_HOSTS-WILDCARD rule
            if target.id == "CORS_ALLOWED_ORIGINS":
                if isinstance(node.value, ast.List):
                    for elt in node.value.elts:
                        if isinstance(elt, ast.Constant) and elt.value == "*":
                            findings.append(Finding(
                                rule_id="SEC-PERMISSIVE-CORS",
                                severity="High",
                                attack_type_exposure="Permissive CORS (Any-Origin Access)",
                                file_path=filepath,
                                line=node.lineno,
                                message="CORS_ALLOWED_ORIGINS contains '*', allowing any website to make cross-origin requests to this API. List explicit trusted origins instead, e.g. ['https://sensemap.abdn.ac.uk'].",
                                standard_ref="OWASP Top 10:2025 A02 – Security Misconfiguration",
                            ))

    return findings


#---RULE 16 SESSION HIJACKING - MISSING COOKIE SECURITY FLAGS---

#Presence check, same shape as Rule 4 (SSL/HSTS) — Django doesn't set
#these cookie protections strictly enough by default, so absence of an
#explicit setting is itself the risk:
#
#SESSION_COOKIE_HTTPONLY = True — stops JavaScript from reading the
#  session cookie at all. Without it, an XSS bug (even a small one)
#  can be used to steal the session cookie directly via script.
#
#SESSION_COOKIE_SECURE = True — stops the cookie being sent over plain
#  HTTP. Without it, the cookie can leak the same way SSL-stripping
#  works (Rule 4) — same MITM risk, different mechanism.
#
#CSRF_COOKIE_SECURE = True — same idea, but for the CSRF token cookie
#  specifically, not the session cookie.

def check_cookie_security_flags(tree, filepath):
    findings = []

    #Only meaningful in settings.py — same scoping reason as Rule 4
    if not filepath.endswith("settings.py"):
        return findings

    #Reuses the same "collect every assigned name" idea as Rule 4
    assigned_names = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name):
                assigned_names.add(target.id)

    required_cookie_flags = (
        "SESSION_COOKIE_HTTPONLY",
        "SESSION_COOKIE_SECURE",
        "CSRF_COOKIE_SECURE",
    )

    missing_flags = [
        flag for flag in required_cookie_flags if flag not in assigned_names
    ]

    if missing_flags:
        findings.append(Finding(
            rule_id="SEC-MISSING-COOKIE-FLAGS",
            severity="High",
            attack_type_exposure="Session Hijacking (Cookie Theft)",
            file_path=filepath,
            line=1,  #presence check, no single line owns an absence — same as Rule 4
            message=f"Missing cookie security setting(s): {', '.join(missing_flags)}. Without these, session/CSRF cookies can be read by JavaScript (XSS-driven theft) or sent over plain HTTP (interception). Add SESSION_COOKIE_HTTPONLY = True, SESSION_COOKIE_SECURE = True, and CSRF_COOKIE_SECURE = True.",
            standard_ref="OWASP Top 10:2025 A04 – Cryptographic Failures",
        ))

    return findings

#---RULE 17 DoS MEMORY EXHAUSTATION - UNBOUNDED QUERYSET SLICE ---
# NEW AST NODE TYPE - ast.Subscript

#4th DoS mechanism in this scanner (after decompression bombs, ReDoS,
#worker starvation). Attacker exploits missing size/quantity limits on
#user input to allocate excessive RAM until the host crashes or OOMs.
#Focuses on VOLUME of data, not one crafted file (that's the
#decompression bomb — same family, different mechanism).
#CWE-400 / CWE-770.
#
#if a queryset slice's (Python's slice syntax something [start:stop] / lower bound (where to start) upper bound (where to stop)
# upper bound comes from user input with no maximum limit, an attacker requests an unbounded number of results in one call
#(?limit=999999999), forcing it all into memory at once.

def check_unbounded_slice(tree, filepath):
    findings = []
    for node in ast.walk(tree):
        #Looking for [...] syntax — e.g. queryset[:20], queryset[5],
        #dict['key']. Only the FIRST check narrows it down; slicing vs
        #plain indexing gets separated next.
        if not isinstance(node, ast.Subscript):
            continue

        #Only care about SLICES (has a ":", like [:20]) — not plain
        #single-item access like queryset[0].
        if not isinstance(node.slice, ast.Slice):
            continue

        #The "upper" is the STOP value of the slice — how far it goes.
        #e.g. in [:20], the upper is 20.
        upper_bound = node.slice.upper

        #No upper value written at all (e.g. queryset[5:]) — not the
        #case this rule targets, skip.
        if upper_bound is None:
            continue

        #SAFE: upper is a fixed number written directly in the code,
        #e.g. [:20] — can't be changed by a user, so it's safe.
        if isinstance(upper_bound, ast.Constant) and isinstance(upper_bound.value, int):
            continue

        #SAFE: upper is wrapped in min(...), e.g. [:min(requested, 100)]
        #— even if "requested" comes from user input, min() still
        #caps the final value at 100 no matter what.
        if isinstance(upper_bound, ast.Call):
            if isinstance(upper_bound.func, ast.Name) and upper_bound.func.id == "min":
                continue

        #Anything else has no visible cap — a bare variable, or a
        #direct request.GET.get(...) with nothing limiting it. Flag it.
        findings.append(Finding(
            rule_id="SEC-UNBOUNDED-SLICE",
            severity="High",
            attack_type_exposure="Memory Exhaustion (Unbounded Data)",
            file_path=filepath,
            line=node.lineno,
            message="This slice's upper bound is not a fixed constant or min()-wrapped value. If it comes from user input with no upper limit (cap),an attacker can request an unbounded number of results in one call, exhausting server memory. Wrap the limit in min(requested, MAX_PAGE_SIZE).",
            standard_ref="CWE-400 – Uncontrolled Resource Consumption",
        ))

    return findings

#---TIER 4 Tier 4 — structural, whole-class walk ---
#this asks a question about an ENTIRE class body at once — "was permission_classes set
#ANYWHERE inside this class?" Can't be answered by looking at any
#single line; requires walking the whole class body first.

#---RULE 18 BROKEN ACCESS CONTROL - PERMISSIONS_CLASSES ALLOW ANY (Via Vertical Privilegue Escalation & Horizontal Privilege Escalation)---
# MISSING AUTH DECORATORS - permission_classes ABSENT 

#Tier 4 — structural, whole-class walk. Different from every rule so
#far: instead of judging one node in isolation, this asks a question
#about an ENTIRE class body at once — "was permission_classes set
#ANYWHERE inside this class?" Can't be answered by looking at any
#single line; requires walking the whole class body first.

#If a DRF view has no permission_classes (or it's explicitly AllowAny),
#ANYONE — authenticated or not — can call it. On a state-changing view
#(submit a report, moderate a tip, admin action), an attacker can
#flood the map with false data or reach admin-only functionality with
#zero authentication.

#Only checks views.py — this pattern is meaningless anywhere else.

DRF_VIEW_BASE_NAMES = ("APIView", "ViewSet", "GenericAPIView", "ModelViewSet")

def check_missing_auth_decorators(tree, filepath):
    findings = []

    if not filepath.endswith("views.py"):
        return findings

    for node in ast.walk(tree):
        #Only care about class definitions
        if not isinstance(node, ast.ClassDef):
            continue

        #Confirm this class actually looks like a DRF view — check its
        #base classes (what it inherits from). node.bases is a list of
        #the parent class expressions, e.g. class Foo(APIView)
        # If it doesn't inherit from a known DRF view type, it's not a view we care about —
        #skip it, so we don't accidentally flag unrelated classes.
        base_names = [
            base.id for base in node.bases if isinstance(base, ast.Name)
        ]
        is_drf_view = any(name in DRF_VIEW_BASE_NAMES for name in base_names)

        if not is_drf_view:
            continue  #not a DRF view class — nothing to check here

        # walk the WHOLE class body looking for permission_classes being assigned anywhere inside it.
        # "whole-class walk" part —  answered only after seeing every line inside this specific class.
        has_permission_classes = False
        is_allow_any = False

        for class_node in ast.walk(node):
            if not isinstance(class_node, ast.Assign):
                continue
            for target in class_node.targets:
                if isinstance(target, ast.Name) and target.id == "permission_classes":
                    has_permission_classes = True

                    #Check if it's specifically set to [AllowAny] —
                    #still unsafe even though the attribute IS present.
                    if isinstance(class_node.value, ast.List):
                        for elt in class_node.value.elts:
                            if isinstance(elt, ast.Name) and elt.id == "AllowAny":
                                is_allow_any = True

        if not has_permission_classes or is_allow_any:
            findings.append(Finding(
                rule_id="SEC-MISSING-AUTH-DECORATOR",
                severity="Critical",
                attack_type_exposure="Broken Access Control",
                file_path=filepath,
                line=node.lineno,
                message=f"'{node.name}' has no permission_classes set (or it's AllowAny). Any user, authenticated or not, can call this view. Set permission_classes = [IsAuthenticated] or stricter.",
                standard_ref="OWASP Top 10:2025 A01 – Broken Access Control",
            ))

    return findings

#---rule 19 BROKEN ACCESS CONTROL - PERMISSIONS_CLASSES ALLOW ANY (Via INSECURE DIRECT OBJECT REFERENCE (IDOR) )---

#Tier 4 — structural, single-METHOD walk.
#  Asks: "does this method fetch an object by ID,
#and if so, does it ALSO call check_object_permissions() somewhere in
#that same method?" Can't be answered from one line alone — needs to
#see the whole method body first.

#IDOR (Insecure Direct Object Reference): if a method fetches an
#object purely by a client-supplied ID with no ownership/permission
#check, an attacker just changes the ID in the URL to read/edit/delete
#someone else's data. Access Tips are ID-addressable and student-
#submitted — exactly the "guess the ID" abuse case.

OBJECT_FETCH_METHOD_NAMES = ("get", "get_object_or_404")

def check_idor_missing_permission(tree, filepath):
    findings = []

    if not filepath.endswith("views.py"):
        return findings

    for node in ast.walk(tree):
        #Only care about function/method definitions
        if not isinstance(node, ast.FunctionDef):
            continue

        #Only care about DRF's object-level methods — retrieve/update/
        #destroy are the standard names for "fetch one object by ID"
        if node.name not in ("retrieve", "update", "destroy", "partial_update"):
            continue

        #Walk THIS METHOD'S body only (ast.walk(node), not the whole
        #tree) — looking for two things inside it:
        fetches_by_id = False
        calls_permission_check = False

        for inner_node in ast.walk(node):
            if isinstance(inner_node, ast.Call):
                #Detects .get(pk=...) or get_object_or_404(...) — a
                #fetch-by-ID call
                if isinstance(inner_node.func, ast.Attribute):
                    if inner_node.func.attr in OBJECT_FETCH_METHOD_NAMES:
                        fetches_by_id = True
                if isinstance(inner_node.func, ast.Name):
                    if inner_node.func.id in OBJECT_FETCH_METHOD_NAMES:
                        fetches_by_id = True

                #Detects self.check_object_permissions(...) anywhere
                #in this method
                if isinstance(inner_node.func, ast.Attribute):
                    if inner_node.func.attr == "check_object_permissions":
                        calls_permission_check = True

        #Only flag if it fetches by ID but NEVER calls the permission
        #check anywhere in the same method
        if fetches_by_id and not calls_permission_check:
            findings.append(Finding(
                rule_id="SEC-IDOR-MISSING-PERMISSION-CHECK",
                severity="Critical",
                attack_type_exposure="Insecure Direct Object Reference (IDOR)",
                file_path=filepath,
                line=node.lineno,
                message=f"'{node.name}' fetches an object by ID with no call to self.check_object_permissions(). An attacker can access another user's object by simply changing the ID. Call self.check_object_permissions(request, obj) after fetching.",
                standard_ref="OWASP Top 10:2025 A01 – Broken Access Control",
            ))

    return findings