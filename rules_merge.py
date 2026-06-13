import os
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
    "ads_pro": "adgads_pro.txt",
    "prv_pro": "adgprv_pro.txt",
    "dns": "adgdns.txt",
    "ads": "adgads.txt",
    "prv": "adgprv.txt"
}

HEADERS = {
    "dns_pro": [
        "! Title: AdGuard Domain",
        "! Description: DNS Filter composed of other filters (AdGuard DNS & Chinese Filter).",
        "! Homepage: https://github.com/elfinallen/filtersmod"
    ],
    "ads_pro": [
        "! Title: AdGuard Advert",
        "! Description: ADS Filter composed of other filters (AdGuard Base & Chinese Filter).",
        "! Homepage: https://github.com/elfinallen/filtersmod"
    ],
    "prv_pro": [
        "! Title: AdGuard Privacy",
        "! Description: Privacy Filter composed of other filters (AdGuard tracking & EasyPrivacy).",
        "! Homepage: https://github.com/elfinallen/filtersmod"
    ],
    "dns": [
        "! Title: AdGuard Domain",
        "! Description: DNS Filter composed of other filters (AdGuard DNS & Chinese Filter), removed uncommon rules.",
        "! Homepage: https://github.com/elfinallen/filtersmod"
    ],
    "ads": [
        "! Title: AdGuard Advert",
        "! Description: ADS Filter composed of other filters (AdGuard Base & Chinese Filter), removed uncommon rules.",
        "! Homepage: https://github.com/elfinallen/filtersmod"
    ],
    "prv": [
        "! Title: AdGuard Privacy",
        "! Description: Privacy Filter composed of other filters (AdGuard tracking & EasyPrivacy), removed uncommon rules.",
        "! Homepage: https://github.com/elfinallen/filtersmod"
    ]
}

# 正则规则
# 注释和白名单
RE_CMT = re.compile(r'^[!#@[]')
# 纯域名规则 ||domain^
RE_DNS = re.compile(r'^\|\|.+\^$')
# 顶级域名
RE_DNS_TLD = re.compile(r'^\|\|.+\.(com|net|org|cn)\^$')
# 特殊域名
RE_DNS_UCM1 = re.compile(r'^\|\|.?.?[-\.\*\d]')
RE_DNS_UCM2 = re.compile(r'^\|\|.+?\.\d+\.')
RE_DNS_UCM3 = re.compile(r'^\|\|(.+\.)?\w+\d+')
RE_DNS_UCM4 = re.compile(r'^\|\|(ad\w|adcs|ajs|alt|amd|ams|anx|apac|api|apm|apps?|apt|atax|ato|att|asg|auth|axp|bdjs|bee|blog|bls|care?|cat|cdn|clog|clk|cnt|code?|core|cpm|crm|css|cts|ctx|dcs|detnmz|dsas|dev|dmc|dms|dsp|easy|eng|etd|etr|evt|ext|fcapi|fcone|fctms|film|fudezz|fpa|fpc|geo|get|ggl|grn|gss|gst|gts|has|hits?|hub|iads?|icon|img|imp|kbx|kra|labs?|live|loc|logs?|logapi|logger|logging|loggw|login|mdt|meds?|media|meta|mms|msg|mtrc?s|nex?t|news?|node|now|nsc|obs|omni?s?|oms|omtr|one|order|osimg|pbcs?|pdmsmrt|pre|prod?|pub|red|reg|res|rtb|rtc|rtk|rtrk|rum|sanl|snal|sapi|sas|sat|sdc|sdk|sdt|seo|set|simg|site|skbx|sms|som|srb|src|srvr?|st\w|starget|start?|stat|stbg|sub|svr|swa|tags?|the|tms|tnc|tpp|traffic|try|tss|ttc|tusk|ulogs?[12]?|umami|user?|utiq|vib|vip|vtd|wctr?|web|website|win|www|xml|xyz|yak)[-\.]')
RE_DNS_UCM5 = re.compile(r'^\|\|(a[abcef]|adima?g|adapi|adclick|adconsole|adebis|admin|adsdk|adser|adsrv|adtrac|advert|advser|agility|ainb|aiq|ana|akoo|alpha|applog|apple|applytic|arab|asset|atten|attr|autom|banner|best|bidder|black|block|bmcdn|browser|bugs|business|butter|buy|bxumze|cafe|campaign|capi|capture|cash|cater|cgcg|chamsoc|chris|clea|click|client|cloud|cname|collect|communicat|config|connect|console|contact|content|continue|conven|conver|cookie|count|creat|cskh|csvt|cueohf|custom|dad|dang|dash|data|date|dati|dcshp|deliv|demand|demo|detail|dich|diem|dien|diff|digest|digi|direct|disco|download|dwga|ebank|ebis|edge|educat|effect|eloqu|elq|email|engage|engine|ensighten|espmp|etrac|ettcc|eul|euro|event|experi|explo|face|fahmta|fairu|fast|fbapi|fbcap|fbs|filter|fine|first|forms|franc|free|garena|gateway|geoba|geoip|geolo|ggai|giao|gift|glob|gnla|goat|gohg|good|goto|gpm|gtm|hcjpb|hdapp|health|heart|hello|hhba|hotro|http|ident|ijaab|image|info|inges|innov|insi|insta|insur|intel|inten|inter|iot|join|kiem|kklq|landing|lazada|lcwfab|learn|lets|lien|link|live|load|lofi|lott|love|lpbhnv|mail|main|manage|market|matomo|maxx|mdws|measure|meet|member|metrik|metrix|mkt|mobil|momo|mundi|mvect|nang|napgame|napkim|napthe|naptie|native|neoss|network|nexus|ngan|nhan|niuk|offen|offer|oncl|onlin|order|ouqo|outreach|page|partner|phan|phie|phil|ping|piwik|pix|platf|plaus|player|prebid|predic|prefer|priva|promo|protec|public|pulse|push|quat|quav|quay|ques|quet|quick|redtrack|register|reklam|repdata|report|research|resource|respons|ressource|revenue|revive|rss|rus|ruttien|saa|safe|sale|sam|sandbox|sarver|script|sdata|seal|seamless|secur|senior|sentry|serv|sgtm|shop|short|show|side|simi|simple|smart|solution|somn|somo|span|ss|srepdata|stape|stati|stats|stepup|stgm|store|strack|subscri|succe|sukie|super|suppo|survey|swim|sxjf|sync|synd|tagg|tagm|taichi|tang|target|tatu|tdk|test|thank|theg|tien|tiki|tin|tkll|tpbank|trail|trang|travel|trac|trck|trk|trungtam|unsubsc|vay|vcb|video|vidie|vie|vii|viol|visit|vj|vn|von|vstvst|want|webcont|webinar|webstat|webtrack|webtraff|webtrekk|welcome|well|widget|wild|xacn|xdyn|xjwht|xrnyh|xscp|xx|ydtzzw|yerbal|ylx|your|yuno|ywrcqa|zzz)')
RE_DNS_KEY = re.compile(r'xn--|cloudfront|weebly|amazonaws|iberostar|appspot|appsflyer|easyjet|adobe|apple|samsung|philips|office|windows|india|metric|analytic|affilia|analysis|analyze|audience|beacon|firebase|monitor|omniture|sponsor|telemetry')
# URL规则
RE_URL1 = re.compile(r'^\|?[-=:%&\?\.\*\w]')
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
        
        # 转小写合并去重
        line_lower = line.lower()

        if rule_type == "dns_pro":
            # 只保留纯域名规则 ||domain^
            if RE_DNS.match(line):
                filtered.add(line_lower)
        
        elif rule_type == "dns":
            if RE_DNS.match(line):
                # 仅保留常见顶级域名、去除特殊域名
                if not RE_DNS_TLD.match(line) or RE_DNS_UCM1.match(line) or RE_DNS_UCM2.match(line) or RE_DNS_UCM3.match(line) or RE_DNS_UCM4.match(line) or RE_DNS_UCM5.match(line) or RE_DNS_KEY.search(line):
                    continue
                # 保留其余规则
                filtered.add(line_lower)
        
        elif rule_type in ["ads_pro", "prv_pro"]:
            # 去除纯域名规则
            if RE_DNS.match(line):
                continue
            # 保留其余规则
            filtered.add(line_lower)
        
        elif rule_type in ["ads", "prv"]:
            # 去除纯域名规则、特殊规则
            if RE_DNS.match(line) or RE_URL1.match(line) or RE_URL2.match(line) or RE_URL3.match(line) or RE_NoS.search(line):
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
    pro_rules = {}
    
    # 处理每一类规则
    for category, urls in SOURCES.items():
        merged_lines = []
        for url in urls:
            merged_lines.extend(fetch_content(url))
        
        # 完全版
        pro_category = f"{category}_pro"
        filtered_pro_rules = filter_rules(merged_lines, pro_category)
        pro_rules[pro_category] = filtered_pro_rules
        
        # 精简版
        filtered_rules = filter_rules(merged_lines, category)
        pro_rules[category] = filtered_rules

    # 写入文件
    for category, rules in pro_rules.items():
        filename = OUTPUT_FILES[category]
        header = HEADERS[category]
        write_file(filename, header, rules)

    # 自动提交
    git_commit_push()

if __name__ == "__main__":
    main()