#dataset

# security_dataset_generator.py
# Generates a JSONL dataset for LLM training:
# fields: {code, language, error_name, vulnerable}
# Covers: Python, C, C++, Java, JavaScript, Go, Rust
# Vulns: A comprehensive set including Buffer Overflow, SQL Injection, Command Injection,
#        Use-after-free, Hardcoded Credentials, XSS, Null Pointer, Integer Overflow,
#        Insecure Deserialization, Resource Leak, and all new requested types.

import random, json, itertools

# ----------- CONFIG -----------
RANDOM_SEED = 1337
SHORT_VARIANTS_PER_TEMPLATE = 100     # per (lang, vuln, safe|unsafe) template
LONG_VARIANTS_PER_TEMPLATE  = 50
OUTPUT_JSONL = "comp.jsonl"

random.seed(RANDOM_SEED)

# ----------- UTILS: human-like noise & naming -----------

# Larger pools of human-ish variable names, with typos & styles
NAME_POOLS = {
    "generic": [
        "data", "input", "inpt", "usr_input", "userInput", "param", "prm", "arg", "args", "payload",
        "name", "username", "usrname", "id", "user_id", "uid", "qid", "val", "value", "cnt", "count", "idx", "index",
        "buf", "buffer", "tmpBuf", "tmp", "tmp1", "tmp2", "tmp_val", "b", "arr", "array", "lst", "list", "numbers",
        "cmd", "command", "cmdStr", "shell_cmd", "arg0", "a0", "opt", "option", "flag", "flg", "path", "pth", "file", "filePath",
        "ptr", "pointer", "p", "px", "ref", "obj", "myObj", "instance", "inst", "ctx", "context", "cfg", "conf", "config",
        "password", "passwd", "pwd", "secret", "token", "tok", "key", "apikey", "api_key", "env", "envvar",
        "cursor", "cur", "c", "stmt", "statement", "st", "sql", "qry", "query", "q", "res", "result", "row", "rows",
        "json", "doc", "docStr", "text", "txt", "str", "s", "t", "x", "y", "z", "n", "m", "password_hash", "passwd_hash",
        "user_agent", "referrer", "cookie", "token", "nonce", "salt", "iv", "cipher", "encrypted_data",
        "conn", "client", "session", "logger", "log", "entry", "event", "message", "file_name", "filename",
        "source", "dest", "req", "res", "request", "response", "body", "header", "creds", "credentials", "user_data",
        "url", "redirect_to", "target", "source", "dest", "file_path", "filename", "temp_file", "upload_path", "upload_dir",
        "lock", "mutex", "sharedResource", "resource", "account", "user_session", "session_id", "secret_key"
    ],
    "python": [
        "cursor", "cur", "conn", "db", "engine", "sess", "session", "f", "fp", "fh", "file", "path", "pth",
        "line", "ln", "content", "contents", "user_input", "unsafe", "clean", "safe", "sanitized", "unsanitized",
        "cmd", "cmd_parts", "cmdline", "args", "argv", "secret_key", "password", "creds", "config", "logger",
        "log_level", "handler", "secure_cookie", "file_path", "filename", "temp_file", "upload_path", "upload_dir"
    ],
    "c_family": [
        "buf", "buffer", "arr", "arr1", "arr2", "b", "tmp", "tmpBuf", "input", "inData", "inpt", "src", "dst",
        "ptr", "p", "px", "pp", "ptr1", "ptr2", "len", "n", "i", "j", "k", "idx", "count", "cap", "size", "sz",
        "capacity", "query", "q", "stmt", "res", "row", "name", "id", "pwd", "pass", "password", "user_agent",
        "user_input", "filename", "path_in", "path_out", "creds", "config_path", "encrypted_data", "cipher",
        "key", "iv", "fd", "file_descriptor", "fp", "log_msg", "log_level", "error_code", "mutex", "lock",
        "thread_id", "status_code", "url", "redirect_url", "file_size"
    ],
    "java": [
        "conn", "stmt", "ps", "rs", "q", "sql", "userInput", "name", "id", "value", "v", "path", "file", "fis",
        "br", "line", "sb", "builder", "cmd", "args", "proc", "pb", "process", "scanner", "password", "secretKey",
        "cipher", "encryptedData", "logMessage", "logger", "fileInputStream", "fileOutputStream", "tempFile",
        "filePath", "uploadPath", "lock", "mutex", "sharedResource", "url", "redirectUrl", "fileSize"
    ],
    "js": [
        "req", "res", "db", "client", "pool", "query", "sql", "params", "name", "id", "val", "value",
        "input", "userInput", "unsafe", "cmd", "cp", "child", "payload", "body", "password", "secret", "token",
        "creds", "config", "filePath", "fileName", "fs", "uploadDir", "logMsg", "logger", "secureCookie",
        "csrf_token", "redirectUrl", "redirectPath", "fileSize"
    ],
    "go": [
        "req", "resp", "db", "stmt", "sql", "query", "payload", "cmd", "path", "file", "conn", "cred",
        "password", "user_input", "user_name", "id", "key", "token", "sess", "logger", "log_msg", "redirect_url"
    ],
    "rust": [
        "req", "res", "db", "stmt", "query", "input", "user_id", "file_path", "path", "buf", "buffer",
        "secret", "key", "token", "cmd", "output", "lock", "mutex", "data", "logger", "log_msg"
    ]
}

COMMENT_POOL = [
    "TODO", "fixme", "DEBUG", "temporary", "refactor later", "check bounds", "needs tests",
    "quick hack", "unsafe?", "review", "optimize", "hot path", "legacy", "don't do this in prod",
    "potential security issue", "this could be a vuln", "danger zone", "fix before deploy",
    "security audit needed", "unsanitized input", "check for TOCTOU"
]

DOCSTRINGS = [
    '"""process data quickly"""',
    '"""utility function"""',
    '"""NOTE: auto-generated"""',
    '"""experimental"""',
    '"""Sanitizes user input for database query."""',
    '"""Handles file upload from a request."""',
    '"""Performs a critical operation."""',
    '"""Logs an error message."""',
    '"""Redirects the user."""',
]

def pick_name(lang_hint=None):
    base = random.choice(NAME_POOLS["generic"])
    if lang_hint and random.random() < 0.5:
        lang_pool = NAME_POOLS.get(lang_hint, [])
        if lang_pool:
            base = random.choice(lang_pool)
    variants = [
        base,
        base.lower(),
        base.upper(),
        base.capitalize(),
        base.replace("_",""),
        base.replace("_","").capitalize(),
        base.replace("_", "") + random.choice(["Data", "Input", "Val", "File"]),
        "tmp" + base.replace("_","").capitalize(),
    ]
    if random.random() < 0.35:
        variants.append(base + str(random.choice([1,2,3,42,99])))
    if random.random() < 0.25:
        variants.append("tmp_" + base)
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
        if random.random() < 0.5:
            return f"{line}  {prefix} {c}"
        else:
            return f"{prefix} {c}\n{line}"
    return line

def maybe_blank_lines(code):
    out = []
    for ln in code.splitlines():
        out.append(ln)
        if random.random() < 0.08:
            out.append("")
    return "\n".join(out)

def indent(block, n=4, ch=" "):
    pad = ch * n
    return "\n".join(pad + ln if ln.strip() else ln for ln in block.splitlines())

def py_wrap_long(body):
    fn = pick_name("python")
    arg = pick_name("python")
    ds = random.choice(DOCSTRINGS)
    pre = [
        "import os", "import sys", "import subprocess", "import json", "import logging",
        "import tempfile", "import datetime", "import re", "import shutil",
        "class FileManager:",
        "    def __init__(self, path):",
        "        self.base_path = path",
        f"def {fn}({arg}):",
        f"    {ds}",
        "    cfg = {'mode': 'dev', 'retry': 1}",
        "    total = 0",
        "    for i in range(3):",
        "        total += i",
        "    # core operation"
    ]
    post = [
        "    # finalize",
        "    logging.info('done with %s', total)",
        "",
        f"if __name__ == '__main__':",
        f"    {fn}({random.choice(['sys.argv','{}','None'])})"
    ]
    return "\n".join(pre + [indent(body, 4)] + post)

def c_wrap_long(body, lang="C"):
    inc = ["#include <stdio.h>", "#include <stdlib.h>", "#include <string.h>", "#include <unistd.h>", "#include <sys/stat.h>"]
    if lang == "C++":
        inc = ["#include <iostream>", "#include <string>", "#include <vector>", "#include <fstream>", "#include <thread>", "#include <mutex>"]
    helper = """
int helper(int n){
    int s = 0;
    for(int i=0;i<n;i++){ s += i; }
    return s;
}
""".strip()
    main_header = "int main(int argc, char** argv){" if lang == "C" else "int main(int argc, char** argv){"
    out = "\n".join(inc) + "\n\n" + helper + "\n\n" + main_header + "\n"
    out += indent("// setup\nint total = helper(5);\n" + body + "\nprintf(\"%d\\n\", total);\n", 4)
    out += "}\n"
    if lang == "C++":
        out = out.replace('printf("%d\\n", total);', 'std::cout << total << std::endl;')
        out += '\n// Class definition to add context\nclass User { public: std::string name; };'
    return out

def java_wrap_long(body):
    cls = (pick_name("java").replace("_","").capitalize() or "App")
    m = pick_name("java")
    pre = f"""
import java.io.*;
import java.util.*;
import java.security.*;
import java.util.logging.Logger;
import java.net.URL;

public class {cls} {{
    private static final Logger LOGGER = Logger.getLogger({cls}.class.getName());
    static int helper(int n){{
        int s=0;
        for(int i=0;i<n;i++) s+=i;
        return s;
    }}
    public void processData(String input) {{
        // helper function context
    }}
    public static void main(String[] args) throws Exception {{
        int total = helper(5);
        LOGGER.info("Starting execution...");
""".strip("\n")
    post = """
        System.out.println(total);
        LOGGER.info("Execution complete.");
    }
}
""".strip("\n")
    return pre + "\n" + indent("// core\n" + body, 8) + "\n" + post

def js_wrap_long(body):
    fn = pick_name("js")
    pre = f"""
const fs = require('fs');
const http = require('http');
const path = require('path');
const crypto = require('crypto');
const logger = require('winston');

function helper(n) {{
    let s = 0;
    for (let i=0;i<n;i++) s+=i;
    return s;
}}

function {fn}(data) {{
    let total = helper(3);
    // core
""".strip("\n")
    post = """
    logger.info("done", total);
}
"""[1:]
    return pre + "\n" + indent(body, 4) + "\n" + post

def go_wrap_long(body):
    fn = pick_name("go")
    pre = f"""
package main

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"log"
)

func helper(n int) int {{
	s := 0
	for i := 0; i < n; i++ {{
		s += i
	}}
	return s
}}

func {fn}(w http.ResponseWriter, r *http.Request) {{
	log.Println("Starting request processing")
	_ = helper(5)
	// core logic
""".strip("\n")
    post = """
	fmt.Fprintf(w, "Done")
	log.Println("Request processed successfully")
}
"""[1:]
    return pre + "\n" + indent(body, 4) + "\n}"

def rust_wrap_long(body):
    fn = pick_name("rust")
    pre = f"""
use std::fs;
use std::path::Path;
use std::sync::Mutex;

fn helper(n: i32) -> i32 {{
    let mut s = 0;
    for i in 0..n {{
        s += i;
    }}
    s
}}

fn {fn}(input: &str) {{
    println!("Starting operation...");
    let _ = helper(5);
    // core logic
""".strip("\n")
    post = """
    println!("Operation complete.");
}
"""[1:]
    return pre + "\n" + indent(body, 4) + "\n}"

def finalize_line(line, lang):
    if lang in ("C","C++","Java","JavaScript", "Go", "Rust"):
        line = maybe_comment(maybe_spaces(line), prefix="//")
    elif lang == "Python":
        line = maybe_comment(maybe_spaces(line), prefix="#")
    return line

def finalize_block(block, lang):
    lines = block.splitlines()
    lines = [finalize_line(ln, lang) if ln.strip() else ln for ln in lines]
    code = "\n".join(lines)
    code = maybe_blank_lines(code)
    return code

# ----------- VULNERABILITY TEMPLATES (unsafe vs safe), per language -----------
TEMPLATES = {
    "Buffer Overflow": {
        "C": {
            "unsafe": ["char {buf}[10]; strcpy({buf}, {input});", "char {buf}[8]; gets({buf});"],
            "safe": ["char {buf}[10]; strncpy({buf}, {input}, sizeof({buf})-1); {buf}[sizeof({buf})-1] = '\\0';", "char {buf}[8]; fgets({buf}, sizeof({buf}), stdin);"]
        },
        "C++": {
            "unsafe": ["char {buf}[10]; std::strcpy({buf}, {input});", "char {buf}[8]; gets({buf}); // legacy"],
            "safe": ["char {buf}[10]; std::strncpy({buf}, {input}, sizeof({buf})-1); {buf}[9]='\\0';", "std::string {dst} = std::string({input}).substr(0, 7);"]
        },
        "Python": {"unsafe": ["{lst} = [0]*10\n{lst}[15] = 5"], "safe": ["{lst} = [0]*10\nif {idx} < len({lst}):\n    {lst}[{idx}] = 5"]},
    },
    "SQL Injection": {
        "Python": {
            "unsafe": ['{cursor}.execute("SELECT * FROM users WHERE name=\\"" + {user_input} + "\\"" )', '{cursor}.execute("DELETE FROM accounts WHERE id=" + str({user_input}))'],
            "safe": ['{cursor}.execute("SELECT * FROM users WHERE name=%s", ({user_input},))', '{cursor}.execute("DELETE FROM accounts WHERE id=%s", ({user_input},))']
        },
        "Java": {
            "unsafe": ['{stmt}.execute("SELECT * FROM users WHERE name=\'" + {user_input} + "\'");', 'String q = "DELETE FROM accounts WHERE id=" + {user_input}; {stmt}.execute(q);'],
            "safe": ['PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name=?"); ps.setString(1, {user_input}); ps.execute();', 'PreparedStatement ps = conn.prepareStatement("DELETE FROM accounts WHERE id=?"); ps.setInt(1, {user_input}); ps.execute();']
        },
        "JavaScript": {
            "unsafe": ['{db}.query("SELECT * FROM users WHERE name=\'" + {user_input} + "\'");', 'let sql = "DELETE FROM accounts WHERE id=" + {user_input}; {db}.query(sql);'],
            "safe": ['{db}.query("SELECT * FROM users WHERE name=$1", [{user_input}]);', 'let sql = "DELETE FROM accounts WHERE id=$1"; {db}.query(sql, [{user_input}]);']
        },
        "Go": {
            "unsafe": ['query := fmt.Sprintf("SELECT * FROM users WHERE id=%s", {user_input})', 'db.Exec(query)'],
            "safe": ['stmt, _ := db.Prepare("SELECT * FROM users WHERE id=?")\nstme.Exec({user_input})']
        },
        "Rust": {
            "unsafe": ['let query = format!("SELECT * FROM users WHERE name=\'{}\'", {user_input});'],
            "safe": ['conn.execute("SELECT * FROM users WHERE name=?", &[&{user_input}]);']
        },
    },
    "Command Injection": {
        "Python": {
            "unsafe": ['os.system("ls " + {cmd})', 'os.popen("ping " + {cmd}).read()'],
            "safe": ['subprocess.run(["ls", {cmd}])', 'subprocess.run(["ping", {cmd}], check=True)']
        },
        "Java": {
            "unsafe": ['Runtime.getRuntime().exec("ls " + {cmd});', 'Runtime.getRuntime().exec("ping " + {cmd});'],
            "safe": ['ProcessBuilder pb = new ProcessBuilder("ls", {cmd}); pb.start();', 'ProcessBuilder pb = new ProcessBuilder("ping", {cmd}); pb.start();']
        },
        "JavaScript": {
            "unsafe": ['require("child_process").exec("ls " + {cmd});', 'require("child_process").exec("ping " + {cmd});'],
            "safe": ['require("child_process").execFile("ls", [{cmd}]);', 'require("child_process").execFile("ping", [{cmd}]);']
        },
        "Go": {
            "unsafe": ['cmd := exec.Command("sh", "-c", "ls " + {cmd}); cmd.Run()'],
            "safe": ['cmd := exec.Command("ls", {cmd}); cmd.Run()']
        },
        "Rust": {
            "unsafe": ['let output = Command::new("sh").arg("-c").arg(format!("echo {}", {input})).output();'],
            "safe": ['let output = Command::new("echo").arg({input}).output();']
        }
    },
    "Use-after-free": {
        "C": {
            "unsafe": ['free({ptr}); printf("%s", {ptr});', 'free({ptr}); {ptr}[0] = \'A\';'],
            "safe": ['free({ptr}); {ptr} = NULL;', 'if ({ptr}) free({ptr}); {ptr} = NULL;']
        },
        "C++": {
            "unsafe": ['delete {ptr}; std::cout << *{ptr};', 'free({ptr}); std::cout << {ptr};'],
            "safe": ['delete {ptr}; {ptr} = nullptr;', 'if ({ptr}) {{ delete {ptr}; {ptr} = nullptr; }}']
        },
    },
    "Hardcoded Credentials": {
        "Python": {
            "unsafe": ['{password} = "1234"', '{password} = "admin_password"'],
            "safe": ['{password} = os.getenv("APP_PASSWORD")', '{password} = json.loads(open("config.json").read()).get("password")']
        },
        "Java": {
            "unsafe": ['String {password} = "root123";'],
            "safe": ['String {password} = System.getenv("DB_PASS");', 'Properties p = new Properties(); p.load(new FileInputStream("app.properties")); String {password} = p.getProperty("db.pass");']
        },
        "JavaScript": {
            "unsafe": ['const {password} = "1234";', 'let {password} = "secret";'],
            "safe": ['const {password} = process.env.DB_PASS;', 'const {password} = JSON.parse(require("fs").readFileSync("config.json")).password;']
        },
        "Go": {
            "unsafe": ['const {password} = "s3cr3t_p4ss";'],
            "safe": ['var {password} = os.Getenv("DB_PASSWORD");']
        },
        "Rust": {
            "unsafe": ['let {secret} = "supersecret";'],
            "safe": ['let {secret} = std::env::var("APP_SECRET").unwrap_or("".to_string());']
        },
    },
    "XSS": {
        "JavaScript": {
            "unsafe": ['element.innerHTML = {user_input};', 'document.write({user_input});'],
            "safe": ['element.textContent = {user_input};', 'element.innerHTML = escapeHtml({user_input});']
        },
        "Python": {
            "unsafe": ['return f"<h1>Hello {user_input}</h1>"'],
            "safe": ['from markupsafe import escape\nreturn f"<h1>Hello {escape(user_input)}</h1>"']
        },
    },
    "Null Pointer": {
        "C": {
            "unsafe": ['{ptr}->method();', 'printf("%s", {ptr});'],
            "safe": ['if ({ptr}) {ptr}->method();', 'if ({ptr} != NULL) printf("%s", {ptr});']
        },
        "C++": {
            "unsafe": ['{ptr}->doStuff();'],
            "safe": ['if ({ptr} != nullptr) {ptr}->doStuff();']
        },
        "Java": {
            "unsafe": ['{obj}.method();'],
            "safe": ['if ({obj} != null) {obj}.method();']
        },
        "Python": {
            "unsafe": ['{obj}.method()'],
            "safe": ['if {obj} is not None:\n    {obj}.method()']
        },
        "JavaScript": {
            "unsafe": ['{obj}.method();'],
            "safe": ['if ({obj}) {obj}.method();']
        },
        "Rust": {
            "unsafe": ['let ptr = std::ptr::null(); let _ = unsafe {{ *ptr }};'],
            "safe": ['let ptr = Some("data"); if let Some(p) = ptr {{ println!("{}", p); }}']
        }
    },
    "Integer Overflow": {
        "C": {
            "unsafe": ['uint8_t {x}=255; {x}+={val};', 'unsigned char {x}=250; {x}+=10;'],
            "safe": ['uint16_t {x}=255; {x}+={val};', 'unsigned int {x}=250; {x}+=10;']
        },
        "C++": {
            "unsafe": ['uint8_t {x}=255; {x}+={val};'],
            "safe": ['unsigned int {x}=255; {x}+={val};']
        },
        "Java": {
            "unsafe": ['int {x} = Integer.MAX_VALUE + 1;'],
            "safe": ['long {x} = (long) Integer.MAX_VALUE + 1;']
        },
        "JavaScript": {
            "unsafe": ['let {x} = Number.MAX_SAFE_INTEGER + 10;'],
            "safe": ['let {x} = BigInt(Number.MAX_SAFE_INTEGER) + 10n;']
        },
        "Python": {
            "unsafe": ['{x} = 255 + 10'],
            "safe": ['{x} = 255 + 10  # Python ints arbitrary precision; no overflow']
        },
        "Rust": {
            "unsafe": ['let {x}: u8 = 255; let _ = {x} + 1;'],
            "safe": ['let {x}: u16 = 255; let _ = {x} + 1;']
        }
    },
    "Insecure Deserialization": {
        "Python": {
            "unsafe": ['pickle.load({user_input})', 'pickle.loads({user_input})'],
            "safe": ['json.loads({safe_data})', 'pickle.loads({safe_data}, fix_imports=False)']
        },
        "Java": {
            "unsafe": ['ObjectInputStream in = new ObjectInputStream({user_input});'],
            "safe": ['JsonObject obj = gson.fromJson({safe_data}, JsonObject.class);']
        },
        "JavaScript": {
            "unsafe": ['eval("(" + {user_input} + ")")'],
            "safe": ['JSON.parse({safe_data})']
        },
    },
    "Resource Leak": {
        "Python": {
            "unsafe": ['{f} = open("data.txt")\n{data} = {f}.read()'],
            "safe": ['with open("data.txt") as {f}:\n    {data} = {f}.read()']
        },
        "Java": {
            "unsafe": ['FileInputStream {fis} = new FileInputStream("file.txt");\nbyte[] buf = new byte[1024];\n{fis}.read(buf);'],
            "safe": ['try (FileInputStream {fis} = new FileInputStream("file.txt")) {\n    byte[] buf = new byte[1024];\n    {fis}.read(buf);\n}']
        },
        "C": {
            "unsafe": ['FILE* {fp} = fopen("file.txt","r"); char buf[128]; fread(buf,1,128,{fp});'],
            "safe": ['FILE* {fp} = fopen("file.txt","r"); if({fp}){{ char buf[128]; fread(buf,1,128,{fp}); fclose({fp}); }}']
        },
        "C++": {
            "unsafe": ['std::ifstream {ifs}("file.txt"); std::string s; {ifs} >> s;'],
            "safe": ['{\n    std::ifstream {ifs}("file.txt");\n    std::string s; {ifs} >> s;\n} // RAII ensures close']
        },
        "Go": {
            "unsafe": ['f, _ := os.Open("file.txt")\nfmt.Println(f.Name())'],
            "safe": ['f, _ := os.Open("file.txt")\ndefer f.Close()\nfmt.Println(f.Name())']
        },
        "Rust": {
            "unsafe": ['let mut f = fs::File::open("data.txt").unwrap();'],
            "safe": ['let mut f = fs::File::open("data.txt").unwrap(); drop(f);']
        }
    },
    "Format String Vulnerabilities": {
        "C": {
            "unsafe": ['printf({user_input});', 'fprintf(stderr, {user_input});'],
            "safe": ['printf("%s", {user_input});', 'fprintf(stderr, "%s", {user_input});']
        },
        "C++": {
            "unsafe": ['printf({user_input});'],
            "safe": ['std::cout << {user_input};']
        },
    },
    "Path Traversal": {
        "Python": {
            "unsafe": ['with open(os.path.join("/var/www/data", {file_name})) as f: pass'],
            "safe": ['safe_path = os.path.join("/var/www/data", os.path.basename({file_name})); with open(safe_path) as f: pass']
        },
        "Java": {
            "unsafe": ['File file = new File(BASE_DIR, {file_name}); FileInputStream fis = new FileInputStream(file);'],
            "safe": ['String safeFileName = new File({file_name}).getName(); File file = new File(BASE_DIR, safeFileName); FileInputStream fis = new FileInputStream(file);']
        },
        "JavaScript": {
            "unsafe": ['const file = path.join("/var/www/data", {file_name}); fs.readFileSync(file);'],
            "safe": ['const file = path.join("/var/www/data", path.basename({file_name})); fs.readFileSync(file);']
        },
        "Go": {
            "unsafe": ['http.ServeFile(w, r, filepath.Join("/var/www/data", {file_name}))'],
            "safe": ['http.ServeFile(w, r, filepath.Join("/var/www/data", filepath.Base({file_name})))']
        },
        "Rust": {
            "unsafe": ['let path = format!("/var/www/data/{}", {file_path}); fs::read_to_string(path);'],
            "safe": ['let path = Path::new("/var/www/data").join(Path::new(&{file_path}).file_name().unwrap()); fs::read_to_string(path);']
        }
    },
    "Insecure Randomness": {
        "Python": {
            "unsafe": ['import random\n{token} = random.randint(1000, 9999)'],
            "safe": ['import secrets\n{token} = secrets.randbits(128)']
        },
        "Java": {
            "unsafe": ['Random rand = new Random(); int {otp} = rand.nextInt(9000) + 1000;'],
            "safe": ['SecureRandom sRand = new SecureRandom(); int {otp} = sRand.nextInt(9000) + 1000;']
        },
        "JavaScript": {
            "unsafe": ['let {val} = Math.random();'],
            "safe": ['let {val} = crypto.randomBytes(16).toString("hex");']
        },
        "Go": {
            "unsafe": ['import "math/rand"\nrand.Seed(time.Now().UnixNano()); {token} := rand.Intn(100)'],
            "safe": ['import "crypto/rand"\nbuf := make([]byte, 16)\nrand.Read(buf)']
        },
        "Rust": {
            "unsafe": ['let token: u32 = random();'],
            "safe": ['use rand::prelude::*;\nlet mut rng = rand::thread_rng();\nlet token: u32 = rng.gen();']
        }
    },
    "Inadequate Encryption": {
        "Python": {
            "unsafe": ['cipher = DES.new(key, DES.MODE_ECB)', 'cipher = AES.new(key, AES.MODE_ECB)'],
            "safe": ['cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)', 'cipher = AES.new(key, AES.MODE_CBC, iv)']
        },
        "Java": {
            "unsafe": ['Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");'],
            "safe": ['Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");']
        },
    },
    "Broken Authentication": {
        "Python": {
            "unsafe": ['if {password} == "admin_password":\n  login_user()'],
            "safe": ['hashed_pw = hash_password({password}); if hashed_pw == stored_hash:\n  login_user()']
        },
        "Java": {
            "unsafe": ['if ({password}.equals("admin")): System.out.println("success");'],
            "safe": ['if (BCrypt.checkpw({password}, storedHash)) System.out.println("success");']
        },
        "JavaScript": {
            "unsafe": ['if ({password} === "password") { res.send("logged in"); }'],
            "safe": ['bcrypt.compare({password}, storedHash, (err, res) => { if(res) login(); });']
        }
    },
    "Improper Error Handling": {
        "Python": {
            "unsafe": ['try:\n  do_something()\nexcept Exception: pass'],
            "safe": ['try:\n  do_something()\nexcept SpecificError as e:\n  logging.error("Failed: %s", e)']
        },
        "Java": {
            "unsafe": ['try { someAction(); } catch (Exception e) {}'],
            "safe": ['try { someAction(); } catch (SpecificException e) { logger.log(Level.SEVERE, "An error occurred", e); }']
        },
        "Go": {
            "unsafe": ['_, err := os.Open("file.txt"); if err != nil { return }'],
            "safe": ['_, err := os.Open("file.txt"); if err != nil { log.Fatal(err) }']
        },
        "Rust": {
            "unsafe": ['let _ = fs::read_to_string("file.txt");'],
            "safe": ['let _ = fs::read_to_string("file.txt").expect("Could not read file");']
        }
    },
    "Race Conditions": {
        "C": {
            "unsafe": ['if (check_file_exists("data.txt")) { open("data.txt", "w"); }'],
            "safe": ['int fd = open("data.txt", O_RDWR | O_CREAT, S_IRWXU); if (fd == -1) { /* handle error */ }']
        },
        "C++": {
            "unsafe": ['if (myMap.count(key)) { do_something(myMap[key]); }'],
            "safe": ['std::lock_guard<std::mutex> lock(mtx);\nif (myMap.count(key)) { do_something(myMap[key]); }']
        },
        "Python": {
            "unsafe": ['if not os.path.exists("tmp.lock"): with open("tmp.lock","w"): pass'],
            "safe": ['import filelock\nwith filelock.FileLock("tmp.lock"): pass']
        },
        "Java": {
            "unsafe": ['if (!myList.isEmpty()) { myList.remove(0); }'],
            "safe": ['synchronized (myList) { if (!myList.isEmpty()) { myList.remove(0); } }']
        },
        "Go": {
            "unsafe": ['if !fileExists("config.json") { createFile("config.json") }'],
            "safe": ['var mu sync.Mutex\nmu.Lock()\ndefer mu.Unlock()\n// operate on shared resource']
        },
        "Rust": {
            "unsafe": ['if Path::new("temp.lock").exists() { fs::write("temp.lock", "data").unwrap(); }'],
            "safe": ['let mut data = mutex.lock().unwrap();\n// safe access']
        }
    },
    "Memory Leaks": {
        "C": {
            "unsafe": ['char* {buf} = (char*)malloc(100);', 'int* {ptr} = new int[50];'],
            "safe": ['char* {buf} = (char*)malloc(100); if ({buf}) { free({buf}); }', 'int* {ptr} = new int[50]; if ({ptr}) { delete[] {ptr}; }']
        },
        "C++": {
            "unsafe": ['int* {ptr} = new int(10);'],
            "safe": ['std::unique_ptr<int> {ptr} = std::make_unique<int>(10);']
        },
        "Rust": {
            "unsafe": ['let data = Box::new([0; 100]); // No explicit deallocation in safe Rust, but for demonstration'],
            "safe": ['let data = Box::new([0; 100]); drop(data);']
        }
    },
    "Insecure Dependencies": {
        "Python": {
            "unsafe": ['# Using un-pinned dependencies'],
            "safe": ['# Using a pinned dependency version\nrequests==2.25.1']
        },
        "Java": {
            "unsafe": ['<dependency>\n  <groupId>commons-collections</groupId>\n  <artifactId>commons-collections</artifactId>\n  <version>3.2.1</version>\n</dependency>'],
            "safe": ['<dependency>\n  <groupId>commons-collections</groupId>\n  <artifactId>commons-collections</artifactId>\n  <version>3.2.2</version>\n</dependency>']
        },
        "Go": {
            "unsafe": ['go get github.com/insecure/lib@latest'],
            "safe": ['go get github.com/secure/lib@v1.2.3']
        }
    },
    "Cross-Site Request Forgery (CSRF)": {
        "Python": {
            "unsafe": ['# no CSRF token check\n@app.route("/transfer", methods=["POST"])\ndef transfer(): pass'],
            "safe": ['# check for CSRF token\n@app.route("/transfer", methods=["POST"])\ndef transfer():\n  validate_csrf({token})']
        },
        "Java": {
            "unsafe": ['// no CSRF token check'],
            "safe": ['// CSRF token check is implemented']
        },
        "JavaScript": {
            "unsafe": ['// no CSRF token included'],
            "safe": ['axios.post("/transfer", { data }, { headers: { "X-CSRF-Token": token } })']
        },
    },
    "Insecure File Upload": {
        "Python": {
            "unsafe": ['filename = {file_name}\nopen(os.path.join(UPLOAD_DIR, filename), "wb").write(file_data)'],
            "safe": ['filename = os.path.basename({file_name})\nif allowed_file(filename):\n  open(os.path.join(UPLOAD_DIR, filename), "wb").write(file_data)']
        },
        "Java": {
            "unsafe": ['String path = UPLOAD_DIR + "/" + {file_name}; FileOutputStream fos = new FileOutputStream(path);'],
            "safe": ['String safeName = FilenameUtils.getName({file_name}); File file = new File(UPLOAD_DIR, safeName);']
        },
        "Go": {
            "unsafe": ['dst, _ := os.Create(filepath.Join(uploadDir, h.Filename))'],
            "safe": ['dst, _ := os.Create(filepath.Join(uploadDir, filepath.Base(h.Filename)))']
        },
        "Rust": {
            "unsafe": ['fs::write(format!("{}/{}", UPLOAD_DIR, {file_name}), {file_data});'],
            "safe": ['let filename = Path::new(&{file_name}).file_name().unwrap(); fs::write(Path::new(UPLOAD_DIR).join(filename), {file_data});']
        }
    },
    "Insufficient Logging & Monitoring": {
        "Python": {
            "unsafe": ['try: os.remove("temp.log")\nexcept: pass'],
            "safe": ['try: os.remove("temp.log")\nexcept Exception as e: logging.error("File deletion failed: %s", e)']
        },
        "Java": {
            "unsafe": ['// missing logging on key events'],
            "safe": ['// proper logging on critical events\nLOGGER.severe("Authentication failed for user: " + username);']
        },
        "Go": {
            "unsafe": ['// no logging on failure'],
            "safe": ['if err != nil { log.Printf("Error: %v", err) }']
        },
        "Rust": {
            "unsafe": ['// missing logging'],
            "safe": ['error!("Failed to process request: {}", e);']
        }
    },
    "Use of Unsafe Functions": {
        "C": {
            "unsafe": ['char {buf}[256]; gets({buf});'],
            "safe": ['char {buf}[256]; fgets({buf}, sizeof({buf}), stdin);']
        },
        "C++": {
            "unsafe": ['char {buf}[256]; gets({buf});'],
            "safe": ['std::string {buf}; std::getline(std::cin, {buf});']
        },
    },
    "Improper Input Validation": {
        "Python": {
            "unsafe": ['if {user_input} == "admin":\n  do_admin_stuff()'],
            "safe": ['if re.match("^[a-zA-Z0-9]+$", {user_input}):\n  if {user_input} == "admin":\n    do_admin_stuff()']
        },
        "Java": {
            "unsafe": ['if ({user_input}.equals("admin")) { doAdminStuff(); }'],
            "safe": ['if ({user_input}.matches("^[a-zA-Z0-9]+$")) { if ({user_input}.equals("admin")) { doAdminStuff(); } }']
        },
        "Go": {
            "unsafe": ['if {user_input} == "admin" { doAdminStuff() }'],
            "safe": ['if isAlphanumeric({user_input}) && {user_input} == "admin" { doAdminStuff() }']
        },
        "Rust": {
            "unsafe": ['if {user_input} == "admin" { do_admin_stuff(); }'],
            "safe": ['if is_alphanumeric(&{user_input}) && {user_input} == "admin" { do_admin_stuff(); }']
        }
    },
    "Weak Password Policy": {
        "Python": {
            "unsafe": ['if len({password}) < 6: return False'],
            "safe": ['if len({password}) < 12 or not re.search("[A-Z]", {password}): return False']
        },
        "Java": {
            "unsafe": ['if ({password}.length() < 6) return false;'],
            "safe": ['if ({password}.length() < 12 || !{password}.matches(".*[A-Z].*")) return false;']
        },
    },
    "Information Exposure": {
        "Python": {
            "unsafe": ['print("Failed to connect to DB: ", e)'],
            "safe": ['logging.error("Failed to connect to DB.")']
        },
        "JavaScript": {
            "unsafe": ['res.status(500).send(e.message);'],
            "safe": ['res.status(500).send("Internal Server Error");']
        },
        "Go": {
            "unsafe": ['http.Error(w, err.Error(), http.StatusInternalServerError)'],
            "safe": ['http.Error(w, "Internal Server Error", http.StatusInternalServerError)']
        },
    },
    "Unsafe Redirects": {
        "Python": {
            "unsafe": ['redirect_to = request.args.get("next")\nreturn redirect(redirect_to)'],
            "safe": ['redirect_to = request.args.get("next")\nif is_safe_url(redirect_to):\n  return redirect(redirect_to)']
        },
        "Java": {
            "unsafe": ['response.sendRedirect(request.getParameter("url"));'],
            "safe": ['String url = request.getParameter("url");\nif (url.startsWith("/app")) response.sendRedirect(url);']
        },
        "JavaScript": {
            "unsafe": ['res.redirect(req.query.target);'],
            "safe": ['const target = req.query.target;\nif (isSafeUrl(target)) res.redirect(target);']
        },
        "Go": {
            "unsafe": ['http.Redirect(w, r, r.URL.Query().Get("url"), http.StatusFound)'],
            "safe": ['redirectURL := r.URL.Query().Get("url")\nif isSafeURL(redirectURL) {\n  http.Redirect(w, r, redirectURL, http.StatusFound)\n}']
        }
    },
    "Time-of-Check to Time-of-Use (TOCTOU)": {
        "Python": {
            "unsafe": ['if os.path.exists("config.json"): os.remove("config.json")'],
            "safe": ['try:\n  os.remove("config.json")\nexcept FileNotFoundError: pass']
        },
        "C": {
            "unsafe": ['if (access("tempfile", F_OK) == 0) { rename("tempfile", "newfile"); }'],
            "safe": ['link("tempfile", "newfile"); unlink("tempfile");']
        },
    }
}

# ----------- PLACEHOLDER FILLING -----------
PLACEHOLDER_HINT = {
    "buf":"c_family","dst":"c_family","src":"c_family",
    "input":"generic","user_input":"generic","safe_data":"generic",
    "cmd":"generic","ptr":"c_family","lst":"python","idx":"python",
    "cursor":"python","stmt":"java","db":"js","f":"python",
    "data":"generic","obj":"generic","x":"generic","val":"generic",
    "fis":"java","fp":"c_family","ifs":"c_family",
    "password":"generic","token":"generic","nonce":"generic","salt":"generic",
    "iv":"generic", "cipher":"generic", "encrypted_data":"generic",
    "file_name":"generic", "filename":"generic", "otp":"generic",
    "redirect_to":"generic", "url":"generic", "redirect_url":"generic",
    "file_data":"generic", "user_session":"generic", "shared_resource":"generic",
    "secret":"generic"
}

def fill_placeholders(template, lang):
    out = template
    found = []
    token = ""
    inside = False
    for ch in template:
        if ch == '{':
            inside = True
            token = ""
        elif ch == '}' and inside:
            inside = False
            found.append(token)
            token = ""
        elif inside:
            token += ch
    
    for key in found:
        hint = PLACEHOLDER_HINT.get(key, None)
        name = pick_name(hint)
        out = out.replace("{"+key+"}", name)
    return out

# ----------- GENERATION -----------
def make_short_variant(snippet, lang):
    code = fill_placeholders(snippet, lang)
    code = finalize_block(code, lang)
    return code

def make_long_variant(snippet, lang):
    core = fill_placeholders(snippet, lang)
    core = finalize_block(core, lang)
    if lang == "Python":
        return py_wrap_long(core)
    if lang == "C":
        return c_wrap_long(core, "C")
    if lang == "C++":
        return c_wrap_long(core, "C++")
    if lang == "Java":
        return java_wrap_long(core)
    if lang == "JavaScript":
        return js_wrap_long(core)
    if lang == "Go":
        return go_wrap_long(core)
    if lang == "Rust":
        return rust_wrap_long(core)
    return core

def generate_all():
    dataset = []
    for vuln, langs in TEMPLATES.items():
        for lang, sets in langs.items():
            for label in ("unsafe","safe"):
                snippets = sets.get(label, [])
                for snip in snippets:
                    for _ in range(SHORT_VARIANTS_PER_TEMPLATE):
                        code = make_short_variant(snip, lang)
                        dataset.append({
                            "code": code,
                            "language": lang,
                            "error_name": vuln,
                            "vulnerable": (label=="unsafe")
                        })
                    for _ in range(LONG_VARIANTS_PER_TEMPLATE):
                        code = make_long_variant(snip, lang)
                        dataset.append({
                            "code": code,
                            "language": lang,
                            "error_name": vuln,
                            "vulnerable": (label=="unsafe")
                        })
    return dataset

if __name__ == "__main__":
    data = generate_all()
    with open(OUTPUT_JSONL, "w", encoding="utf-8") as f:
        for row in data:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"Generated {len(data)} samples into {OUTPUT_JSONL}")
