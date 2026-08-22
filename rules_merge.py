import re
import requests
import subprocess
from datetime import datetime

SOURCES = {
    "dns": [
        "https://filters.adtidy.org/android/filters/15_optimized.txt",
        "https://filters.adtidy.org/android/filters/224_optimized.txt"
    ],
    "ads": [
        "https://filters.adtidy.org/android/filters/2_optimized.txt",
        "https://filters.adtidy.org/android/filters/224_optimized.txt"
    ],
    "prv": [
        "https://filters.adtidy.org/android/filters/3_optimized.txt",
        "https://filters.adtidy.org/android/filters/118_optimized.txt"
    ]
}

OUTPUT_FILES = {
    "dns_pro": "adgdns_pro.txt",
    "dns": "adgdns.txt",
    "ads": "adgads.txt",
    "prv": "adgprv.txt"
}

HEADERS = {
    "dns_pro": [
        "! Title: AdGuard Domain",
        "! Description: DNS Filter composed of AdGuard DNS & Chinese Filter.",
        "! Homepage: https://github.com/elfinallen/filtersmod"
    ],
    "dns": [
        "! Title: AdGuard Domain",
        "! Description: DNS Filter composed of AdGuard DNS & Chinese Filter, removed uncommon rules.",
        "! Homepage: https://github.com/elfinallen/filtersmod"
    ],
    "ads": [
        "! Title: AdGuard Advert",
        "! Description: ADS Filter composed of AdGuard Base & Chinese Filter, removed uncommon rules.",
        "! Homepage: https://github.com/elfinallen/filtersmod"
    ],
    "prv": [
        "! Title: AdGuard Privacy",
        "! Description: Privacy Filter composed of AdGuard tracking & EasyPrivacy, removed uncommon rules.",
        "! Homepage: https://github.com/elfinallen/filtersmod"
    ]
}

# 正则规则
# 注释和白名单
RE_CMT = re.compile(r'^[!#@[]')
# 纯域名规则 ||domain^
RE_DNS = re.compile(r'^\|\|.+\^$')
# 顶级域名
RE_DNS_TLD = re.compile(r'^\|\|.+\.(com|net|org|cn|cc|io|top)\^$')
# 特殊域名
RE_DNS_UCM1 = re.compile(r'^\|\|.?.?.?[-\.\*\d]')
RE_DNS_UCM2 = re.compile(r'^\|\|.+\.\d+\.')
RE_DNS_UCM3 = re.compile(r'^\|\|(.+\.)?\w+\d+')
RE_DNS_UCM4 = re.compile(r'^\|\|(adcs|apac|apps|atax|auth|auto|beap|bear|bdjs|bird|bison|blog|bridge|buzz|cafi|cane|canvas|cattle|care|cdns|cdnx|check|clog|code|core|conv|control|cpro|cqpmvc|csst|daima|detnmz|dgwa|doppler|dsas|easy|emea|emst|ewstv|exch|expo|falcon|faro|fashion|feed|ferret|fcapi|fcone|fctms|files?|fire|film|five|flag|flash|flea|flow|flurry|flux|follow|food|form|fudezz|gerbil|getloomax|gold|gorilla|great|grow|growth|hits|hornet|horse|hruk|iads|icon|kiwi|klik|know|koala|labs|leads?|lemon|lime|lists?|live|llama|look|logs|logapi|logger|logging|loggw|login|meds|media|meta|milanss|module|mtcvyv|mtgs|mtrc?s|next|news|node|nossl|omni?s?|omtr|order|os?img|parrot|party|path|pbcs|perf|pdmsmrt|piatra|pillar|piranha|portal|prod|qzwktr|reach|read|relay|remark|rest|results|rise|road|rook|rover|rtrk|signal|signup|sanl|snal|sapi|simg|site|skbx|srvs|srvr|starget|start?|stat|stbg|stream|swebstats|swordfish|tags|teal|tech|tigershark|tmsc|toad|tools?|traffic|trust|tryme|ttkk|tusk|ulogs?[12]?|umami|usage|user|utiq|wctr|website)[-\.]')
RE_DNS_UCM5 = re.compile(r'^\|\|(a[abcef]|adima?g|adapi|adclick|adconsole|adebis|admin|adsdk|adser|adsrv|adtrac|advert|advser|agility|ainb|aiq|ana|answers|anteater|antelope|akoo|alpha|apiv|applog|apple|applytic|arab|asset|atten|attr|autom|banner|best|bidder|black|block|bmcdn|browser|bugs|business|butter|buy|bxumze|cafe|call|campaign|capi|capture|cash|cater|cgcg|chamsoc|chick|child|chinhphu|chris|clea|click|client|cloud|cname|collect|communicat|config|connect|console|consent|container|contact|content|continue|conven|conver|cookie|count|creat|cskh|csvt|cueohf|custom|dad|dang|dash|data|date|dati|dcshp|deliv|demand|demo|detail|dich|diem|dien|diff|digest|digi|direct|disco|download|dwga|ebank|ebis|edge|educat|effect|eloqu|elq|email|engage|engine|ensighten|erdev|espmp|etrac|ettcc|eul|euro|event|experi|explo|face|fahmta|fairu|fast|fbapi|fbcap|fbs|filter|fine|first|flaca|forms|franc|free|garena|gateway|geoba|geoip|geolo|ggai|giao|gift|glob|gnla|goat|gohg|good|goto|gpm|gtm|hcjpb|hdapp|health|heart|hello|hhba|host|hotro|http|hydra|ident|ijaab|image|info|inges|innov|insi|insta|insur|intel|inten|inter|iot|join|k[fgh]|kiem|kklq|landing|lazada|lcwfab|lcacaen|learn|lets|lien|link|live|load|lofi|lott|love|lpbhnv|mail|main|manage|market|matomo|maxx|mdws|measure|meet|member|metrik|metrix|mkt|mobil|momo|mundi|mvect|nang|napgame|napkim|napthe|naptie|native|neoss|network|nexus|ndpro|ngan|nhan|niuk|offen|offer|oncl|onlin|order|ouqo|outreach|page|partner|phan|phie|phil|ping|piwik|pix|platf|plaus|player|prebid|predic|prefer|priva|promo|protec|public|pulse|push|quat|quav|quay|ques|quet|quick|redtrack|register|reklam|repdata|report|research|resource|respons|ressource|revenue|revive|rss|rus|ruttien|saa|safe|sale|sam|sandbox|sarver|script|sdata|seal|seamless|secur|senior|sentry|serv|sgtm|shop|short|show|side|simi|simple|sitecat|sleepzee|smart|solution|somn|somo|span|ss|srepdata|stag|stape?|stati|stats|stepup|stgm|store|strack|subscri|succe|sukie|super|suppo|survey|swim|sxjf|sync|synd|tagg|tagm|taichi|tang|target|tatu|telegraph|tdk|test|thank|theg|tien|tiki|tin|tkll|tpbank|trail|trang|travel|trac|trck|trk|trungtam|unsubsc|vay|vcb|video|vidie|vie|vii|viol|visit|vj|vn|vmt|von|vstvst|want|webcont|webinar|webstat|webt|welcome|well|widget|wild|xacn|xdyn|xjwht|xrnyh|xscp|xx|ydtzzw|yerbal|ylx|your|yuno|ywrcqa|zapfie|zzz)')
RE_DNS_KEY = re.compile(r'xn--|cloudfront|weebly|amazonaws|iberostar|appspot|appsflyer|easyjet|adobe|apple|samsung|philips|office|windows|india|metric|analytic|affilia|analysis|analyze|audience|beacon|firebase|monitor|omniture|sponsor|telemetry|tracking|tindung')
# URL规则
RE_URL1 = re.compile(r'^\|?[-=:%&\?\.\*\w]|^\|\|\*')
RE_URL2 = re.compile(r'^\/[\d\W_]')
RE_URL3 = re.compile(r'^\/.+\/$')
# 修饰规则
RE_NoS = re.compile(r'\$|#')

def fetch_content(url):
    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        return resp.text.splitlines()
    except Exception as e:
        return []

def filter_rules(lines, rule_type):
    filtered = set()
    for line in lines:
        line = line.strip()
        if not line or RE_CMT.match(line):
            continue
        
        line_lower = line.lower()

        if rule_type == "dns_pro":
            if RE_DNS.match(line):
                filtered.add(line_lower)
        
        elif rule_type == "dns":
            # 仅保留常见顶级域名、去除特殊域名
            if not RE_DNS.match(line) or not RE_DNS_TLD.match(line) or RE_DNS_UCM1.match(line) or RE_DNS_UCM2.match(line) or RE_DNS_UCM3.match(line) or RE_DNS_UCM4.match(line) or RE_DNS_UCM5.match(line) or RE_DNS_KEY.search(line):
                continue
            filtered.add(line_lower)
        
        elif rule_type in ["ads", "prv"]:
            # 去除纯域名规则、IP和数字域名规则、特殊规则
            if RE_DNS.match(line) or RE_DNS_UCM2.match(line) or RE_URL1.match(line) or RE_URL2.match(line) or RE_URL3.match(line) or RE_NoS.search(line):
                continue
            # 保留其余规则
            filtered.add(line_lower)
    
    return sorted(list(filtered))

def write_file(filename, header_lines, rules):
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    with open(filename, "w", encoding="utf-8") as f:
        for h in header_lines:
            f.write(f"{h}\n")
        f.write(f"! Last Updated: {timestamp}\n")
        f.write(f"! Total Rules: {len(rules)}\n")
        f.write(f"! Expires: 5 days\n")
        for rule in rules:
            f.write(f"{rule}\n")

def git_commit_push():
    subprocess.run(["git", "config", "--local", "user.email", "github-actions[bot]@users.noreply.github.com"])
    subprocess.run(["git", "config", "--local", "user.name", "github-actions[bot]"])
    
    # 检查是否有变更
    status = subprocess.run(["git", "status", "--porcelain"], capture_output=True, text=True)
    if not status.stdout.strip():
        return

    # 添加、提交、推送
    subprocess.run(["git", "add", "."])
    commit_msg = f"auto update {datetime.utcnow().strftime('%Y-%m-%d %H:%M')}"
    subprocess.run(["git", "commit", "-m", commit_msg])
    subprocess.run(["git", "push"])
    
def main():
    all_rules = {}

    for category, urls in SOURCES.items():
        merged_lines = []
        for url in urls:
            merged_lines.extend(fetch_content(url))

        if category == "dns":
            pro_key = f"{category}_pro"
            all_rules[pro_key] = filter_rules(merged_lines, pro_key)

        all_rules[category] = filter_rules(merged_lines, category)

    for category, rules in all_rules.items():
        filename = OUTPUT_FILES[category]
        header   = HEADERS[category]
        write_file(filename, header, rules)

    git_commit_push()

if __name__ == "__main__":
    main()