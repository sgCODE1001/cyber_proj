# security_dataset_generator_full.py
# Generates a JSONL dataset for LLM training:
# fields: {code, language, error_name, vulnerable}
# Languages: Python, C, C++, Java, JavaScript, Go, Rust
# Vulnerabilities: all included + realistic variable naming, human mistakes, multiple variations

import random
import json

# ----------- CONFIG -----------
RANDOM_SEED = 1337
SHORT_VARIANTS_PER_TEMPLATE = 20
OUTPUT_JSONL = "security_dataset.jsonl"

random.seed(RANDOM_SEED)

# ----------- UTILITIES: human-like names, comments, spacing, blanks -----------

NAME_POOLS = {
    "generic": ["data","input","inpt","usr_input","userInput","param","prm","arg","args","payload","name","username",
                "usrname","id","user_id","uid","qid","val","value","cnt","count","idx","index","buf","buffer","tmpBuf",
                "tmp","tmp1","tmp2","tmp_val","b","arr","array","lst","list","numbers","cmd","command","cmdStr",
                "shell_cmd","arg0","a0","opt","option","flag","flg","path","pth","file","filePath","ptr","pointer",
                "p","px","ref","obj","myObj","instance","inst","ctx","context","cfg","conf","config","password","passwd",
                "pwd","secret","token","tok","key","apikey","api_key","env","envvar","cursor","cur","c","stmt","statement",
                "st","sql","qry","query","q","res","result","row","rows","json","doc","docStr","text","txt","str","s","t",
                "x","y","z","n","m","password_hash","passwd_hash","user_agent","referrer","cookie","nonce","iv","cipher",
                "encrypted_data","conn","client","session","logger","log","entry","event","message","file_name","filename",
                "source","dest","req","res","request","response","body","header","creds","credentials","user_data","url",
                "redirect_to","target","file_path","temp_file","upload_path","upload_dir","lock","mutex","sharedResource",
                "resource","account","user_session","session_id","secret_key"],
    "python": ["cursor","cur","conn","db","engine","sess","session","f","fp","fh","file","path","line","user_input",
               "unsafe","clean","safe","sanitized","lst","index","val"],
    "c_family": ["buf","buffer","arr","arr1","arr2","b","tmp","tmpBuf","input","ptr","p","px","pp","ptr1","ptr2","len","n","i","j","k"],
    "java": ["conn","stmt","ps","rs","q","sql","userInput","name","id","value","v","path","file","fis","br","line",
             "sb","builder","cmd","args","proc"],
    "js": ["req","res","db","client","pool","query","sql","params","input","userInput","unsafe","cmd","payload","body","password","secret","token"],
    "go": ["req","resp","db","stmt","sql","query","payload","cmd","path","file","conn","cred","password","user_input","user_name","id","key","token"],
    "rust": ["req","res","db","stmt","query","input","user_id","file_path","path","buf","buffer","secret","key","token","cmd","output","lock","mutex"]
}

COMMENT_POOL = ["TODO","fixme","DEBUG","temporary","refactor later","check bounds","needs tests",
                "quick hack","unsafe?","review","optimize","hot path","legacy","don't do this in prod",
                "potential security issue","this could be a vuln","danger zone","fix before deploy",
                "security audit needed","unsanitized input","check for TOCTOU"]

PLACEHOLDER_HINT = {
    "buf":"c_family","dst":"c_family","src":"c_family","input":"generic","user_input":"generic",
    "safe_data":"generic","cmd":"generic","ptr":"c_family","lst":"python","idx":"python",
    "cursor":"python","stmt":"java","db":"js","f":"python","data":"generic","obj":"generic",
    "x":"generic","val":"generic","fis":"java","fp":"c_family","ifs":"c_family","password":"generic",
    "token":"generic","nonce":"generic","salt":"generic","iv":"generic","cipher":"generic",
    "encrypted_data":"generic","file_name":"generic","filename":"generic","otp":"generic",
    "redirect_to":"generic","url":"generic","redirect_url":"generic","file_data":"generic",
    "user_session":"generic","shared_resource":"generic","secret":"generic"
}

def pick_name(lang_hint=None):
    base = random.choice(NAME_POOLS["generic"])
    if lang_hint and random.random() < 0.5:
        lang_pool = NAME_POOLS.get(lang_hint, [])
        if lang_pool:
            base = random.choice(lang_pool)
    variants = [base, base.lower(), base.upper(), base.capitalize(), base.replace("_",""), base.replace("_","").capitalize()]
    if random.random() < 0.35: variants.append(base+str(random.choice([1,2,3,42,99])))
    if random.random() < 0.25: variants.append("tmp_"+base)
    return random.choice(variants)

def maybe_spaces(s):
    s = s.replace("=", random.choice(["=", " = ", "  ="]))
    s = s.replace("+", random.choice(["+", " + ", " +"]))
    s = s.replace("(", random.choice(["(", "( ", "("]))
    s = s.replace(")", random.choice([")", " )", ")"]))
    s = s.replace(",", random.choice([",", ", ", " , "]))
    return s

def maybe_comment(line, prefix="//"):
    if random.random() < 0.25:
        c = random.choice(COMMENT_POOL)
        if random.random() < 0.5: return f"{line}  {prefix} {c}"
        else: return f"{prefix} {c}\n{line}"
    return line

def maybe_blank_lines(code):
    out=[]
    for ln in code.splitlines():
        out.append(ln)
        if random.random() < 0.08: out.append("")
    return "\n".join(out)

def finalize_line(line, lang):
    if lang in ("C","C++","Java","JavaScript","Go","Rust"): line = maybe_comment(maybe_spaces(line), prefix="//")
    elif lang == "Python": line = maybe_comment(maybe_spaces(line), prefix="#")
    return line

def finalize_block(block, lang):
    lines = block.splitlines()
    lines = [finalize_line(ln, lang) if ln.strip() else ln for ln in lines]
    code = "\n".join(lines)
    code = maybe_blank_lines(code)
    return code

def fill_placeholders(template, lang):
    out = template
    found = []
    token = ""
    inside = False
    for ch in template:
        if ch == '{': inside=True; token=""
        elif ch == '}' and inside: inside=False; found.append(token); token=""
        elif inside: token+=ch
    for key in found:
        hint = PLACEHOLDER_HINT.get(key, None)
        name = pick_name(hint)
        out = out.replace("{"+key+"}", name)
    return out

def make_short_variant(snippet, lang):
    code = fill_placeholders(snippet, lang)
    return finalize_block(code, lang)

# ----------- FULL VULNERABILITY TEMPLATES -----------
TEMPLATES = {
    "Buffer Overflow": {
        "C": {
            "unsafe": ["char {buf}[10]; strcpy({buf},{data});"],
            "safe": ["char {buf}[10]; strncpy({buf},{data},sizeof({buf})-1); {buf}[sizeof({buf})-1]='\\0';"]
        },
        "C++": {
            "unsafe": ["char {buf}[10]; std::strcpy({buf},{data});"],
            "safe": ["char {buf}[10]; std::strncpy({buf},{data},sizeof({buf})-1); {buf}[sizeof({buf})-1]='\\0';"]
        },
        "Python": {
            "unsafe": ["{lst}=[0]*10; {lst}[15]=5"],
            "safe": ["{lst}=[0]*10; if {idx}<len({lst}): {lst}[{idx}]=5"]
        }
    },
    "SQL Injection": {
        "Python": {
            "unsafe": ['{cursor}.execute("SELECT * FROM users WHERE name=\'"+{user_input}+"\'")'],
            "safe": ['{cursor}.execute("SELECT * FROM users WHERE name=%s", ({user_input},))']
        },
        "Java": {
            "unsafe": ['{stmt}.execute("SELECT * FROM users WHERE name=\'"+{user_input}+"\'")'],
            "safe": ['PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name=?"); ps.setString(1,{user_input}); ps.execute();']
        },
        "JavaScript": {
            "unsafe": ['{db}.query("SELECT * FROM users WHERE name=\'"+{user_input}+"\'")'],
            "safe": ['{db}.query("SELECT * FROM users WHERE name=$1", [{user_input}])']
        },
        "Go": {
            "unsafe": ['query := fmt.Sprintf("SELECT * FROM users WHERE id=%s", {user_input})'],
            "safe": ['stmt, _ := db.Prepare("SELECT * FROM users WHERE id=?"); stmt.Exec({user_input})']
        },
        "Rust": {
            "unsafe": ['let q = format!("SELECT * FROM users WHERE name=\'{}\'", {user_input});'],
            "safe": ['conn.execute("SELECT * FROM users WHERE name=?", &[&{user_input}]);']
        }
    },
    "Command Injection": {
        "Python": {
            "unsafe": ['os.system("ls "+{cmd})'],
            "safe": ['subprocess.run(["ls",{cmd}])']
        },
        "Java": {
            "unsafe": ['Runtime.getRuntime().exec("ls "+{cmd});'],
            "safe": ['ProcessBuilder pb = new ProcessBuilder("ls",{cmd}); pb.start();']
        },
        "JavaScript": {
            "unsafe": ['require("child_process").exec("ls "+{cmd});'],
            "safe": ['require("child_process").execFile("ls",[ {cmd} ]);']
        },
        "Go": {
            "unsafe": ['cmd := exec.Command("sh","-c","ls "+{cmd}); cmd.Run()'],
            "safe": ['cmd := exec.Command("ls",{cmd}); cmd.Run()']
        },
        "Rust": {
            "unsafe": ['let output = Command::new("sh").arg("-c").arg(format!("echo {}",{cmd})).output();'],
            "safe": ['let output = Command::new("echo").arg({cmd}).output();']
        }
    },
    "Use-after-free": {
        "C": {
            "unsafe": ["free({ptr}); printf(\"%s\", {ptr});"],
            "safe": ["free({ptr}); {ptr}=NULL;"]
        },
        "C++": {
            "unsafe": ["delete {ptr}; std::cout << *{ptr};"],
            "safe": ["delete {ptr}; {ptr}=nullptr;"]
        }
    },
    "Hardcoded Credentials": {
        "Python": {"unsafe": ['password="{password}"'], "safe": ['password = os.getenv("PASSWORD")']},
        "Java": {"unsafe": ['String password="{password}";'], "safe": ['String password = System.getenv("PASSWORD");']},
        "C": {"unsafe": ['char password[]="{password}";'], "safe": ['char password[100]; get_env("PASSWORD",password,100);']}
    },
    "XSS": {
        "JavaScript": {"unsafe": ['document.innerHTML={user_input};'], "safe": ['document.textContent={user_input};']},
        "Python": {"unsafe": ['return "<div>"+{user_input}+"</div>"'], "safe": ['return escape({user_input})']}
    },
    "Null Pointer": {
        "C": {"unsafe":["printf(\"%s\",*{ptr});"],"safe":["if({ptr}) printf(\"%s\",*{ptr});"]},
        "C++":{"unsafe":["std::cout << *{ptr};"],"safe":["if({ptr}) std::cout << *{ptr};"]}
    },
    "Integer Overflow": {
        "C":{"unsafe":["int x=INT_MAX; x=x+1;"],"safe":["int x=INT_MAX; if(x<INT_MAX) x=x+1;"]},
        "Python":{"unsafe":["x=2**31-1; y=x+1"],"safe":["x=2**31-1; y=x if x==2**31-1 else x+1"]}
    },
    "Insecure Deserialization": {
        "Python":{"unsafe": ['pickle.loads({data})'], "safe": ['json.loads({data})']},
        "Java":{"unsafe": ['ObjectInputStream ois = new ObjectInputStream(fis); Object obj = ois.readObject();'],
                "safe": ['// Validate input schema before deserialization']}
    },
    "Resource Leak": {
        "Python":{"unsafe": ['f = open("file.txt"); f.read()'], "safe": ['with open("file.txt") as f: f.read()']},
        "C":{"unsafe": ['FILE *f=fopen("file.txt","r");'], "safe": ['FILE *f=fopen("file.txt","r"); if(f) fclose(f);']}
    },
    "Format String": {
        "C":{"unsafe": ['printf({user_input});'], "safe": ['printf("%s", {user_input});']},
        "Python":{"unsafe": ['print({user_input}%s)'], "safe": ['print("%s"%{user_input})']}
    },
    "Path Traversal": {
        "Python":{"unsafe": ['open("/etc/"+{user_input})'], "safe": ['open(os.path.join("/etc", os.path.basename({user_input})))']},
        "Java":{"unsafe": ['new File("/etc/"+{user_input});'], "safe": ['new File("/etc/", new File({user_input}).getName());']}
    },
    "Insecure Randomness": {
        "Python":{"unsafe": ['random.seed(123); x=random.randint(0,100)'], "safe": ['secrets.randbelow(100)']},
        "Java":{"unsafe": ['Random r = new Random(123);'], "safe": ['SecureRandom r = new SecureRandom();']}
    },
    "Inadequate Encryption": {
        "Python":{"unsafe": ['hashlib.md5({data})'], "safe": ['hashlib.sha256({data})']},
        "Java":{"unsafe": ['MessageDigest.getInstance("MD5")'], "safe": ['MessageDigest.getInstance("SHA-256")']}
    },
    "Broken Authentication": {
        "Python":{"unsafe": ['if password=="{password}": pass'], "safe": ['authenticate(password)']}
    },
    "Improper Error Handling": {
        "Python":{"unsafe": ['try: x=1/0 except: pass'], "safe": ['try: x=1/0 except ZeroDivisionError as e: log(e)']}
    },
    "Race Conditions": {
        "Python":{"unsafe": ['if not os.path.exists(f): open(f,"w")'], "safe": ['with open(f,"x") as fd: pass']}
    },
    "Memory Leaks": {
        "C":{"unsafe": ['ptr=malloc(100); ptr=malloc(100);'], "safe": ['ptr=malloc(100); free(ptr);']}
    },
    "Insecure Dependencies": {
        "Python":{"unsafe": ['import requests==2.18.0'], "safe": ['import requests>=2.31.0']}
    },
    "CSRF": {
        "JavaScript":{"unsafe": ['fetch("/transfer",{method:"POST",body:{payload}})'], "safe": ['fetch("/transfer",{method:"POST",body:{payload},headers:{"X-CSRF-Token":token}})']}
    },
    "Insecure File Upload": {
        "Python":{"unsafe": ['open({user_input},"wb").write(data)'], "safe": ['if validate({user_input}): open({user_input},"wb").write(data)']}
    },
    "Insufficient Logging & Monitoring": {
        "Python":{"unsafe": ['pass'], "safe": ['log("Important event")']}
    },
    "Unsafe Functions": {
        "C":{"unsafe": ['gets({buf});'], "safe": ['fgets({buf}, sizeof({buf}), stdin);']}
    },
    "Improper Input Validation": {
        "Python":{"unsafe": ['eval({user_input})'], "safe": ['safe_eval({user_input})']}
    },
    "Weak Password Policy": {
        "Python":{"unsafe": ['if len(password)<4: pass'], "safe": ['if len(password)<8: raise ValueError()']}
    },
    "Information Exposure": {
        "Python":{"unsafe": ['print(secret_key)'], "safe": ['log("Accessed key")']}
    },
    "Unsafe Redirects": {
        "Python":{"unsafe": ['redirect({user_input})'], "safe": ['if validate_url({user_input}): redirect({user_input})']}
    },
    "TOCTOU": {
        "Python":{"unsafe": ['if os.path.exists(f): open(f,"w")'], "safe": ['with open(f,"x") as fd: pass']}
    }
}


# ----------- DATASET GENERATION -----------
dataset = []
for vuln_name, lang_dict in TEMPLATES.items():
    for lang, variants in lang_dict.items():
        for v_type, snippets in variants.items():
            vulnerable = (v_type=="unsafe")
            for snippet in snippets:
                for _ in range(SHORT_VARIANTS_PER_TEMPLATE):
                    code = make_short_variant(snippet, lang)
                    dataset.append({
                        "code": code,
                        "language": lang,
                        "error_name": vuln_name,
                        "vulnerable": vulnerable
                    })

# ----------- SAVE JSONL -----------
with open(OUTPUT_JSONL, "w") as f:
    for entry in dataset:
        f.write(json.dumps(entry)+"\n")

print(f"Generated {len(dataset)} code snippets in {OUTPUT_JSONL}")
