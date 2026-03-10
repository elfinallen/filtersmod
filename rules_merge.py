import os
import re
import requests
import subprocess
from datetime import datetime

# 配置部分
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
        "! Description: DNS Filter composed of other filters (AdGuard DNS & Chinese Filter)",
        "! Homepage: https://github.com/elfinallen/filtersmod"
    ],
    "ads_pro": [
        "! Title: AdGuard Advert",
        "! Description: ADS Filter composed of other filters (AdGuard Base & Chinese Filter)",
        "! Homepage: https://github.com/elfinallen/filtersmod"
    ],
    "prv_pro": [
        "! Title: AdGuard Privacy",
        "! Description: Privacy Filter composed of other filters (AdGuard tracking & EasyPrivacy)",
        "! Homepage: https://github.com/elfinallen/filtersmod"
    ],
    "dns": [
        "! Title: AdGuard Domain",
        "! Description: DNS Filter composed of other filters (AdGuard DNS & Chinese Filter), removed uncommon rules",
        "! Homepage: https://github.com/elfinallen/filtersmod"
    ],
    "ads": [
        "! Title: AdGuard Advert",
        "! Description: ADS Filter composed of other filters (AdGuard Base & Chinese Filter), removed uncommon rules",
        "! Homepage: https://github.com/elfinallen/filtersmod"
    ],
    "prv": [
        "! Title: AdGuard Privacy",
        "! Description: Privacy Filter composed of other filters (AdGuard tracking & EasyPrivacy), removed uncommon rules",
        "! Homepage: https://github.com/elfinallen/filtersmod"
    ]
}

# 正则规则
# 注释和白名单
RE_CMT = re.compile(r'^!|^#|^@|^\[')
# 纯域名规则 ||domain^
RE_DNS = re.compile(r'^\|\|[^/]+\^$')
# 顶级域名
RE_DNS_TLD = re.compile(r'^\|\|[^/]+\.(com|net|org|cn)\^$')
# 二级域名
RE_DNS_SEC1 = re.compile(r'^\|\|[^/]+\.cloudfront\.net\^$')
RE_DNS_SEC2 = re.compile(r'^\|\|[^/]+\.(weebly|amazonaws|iberostar|appspot|appsflyer|appsflyersdk|easyjet)\.com\^$')
# 不常用域名
RE_DNS_UCM1 = re.compile(r'adobe|apple|samsung|philips|office|windows|xn--|india')
RE_DNS_UCM2 = re.compile(r'metric|analytic|affilia|analysis|analyze|audience|beacon|firebase|monitor|omniture|sponsor|telemetry')
# 域名开头 
RE_DNS_STR1 = re.compile(r'^\|\|ad[cvx][-\.]')
RE_DNS_STR2 = re.compile(r'^\|\|(a|ad|ads)?[-\*\.]')
RE_DNS_STR3 = re.compile(r'^\|\|(ad|ad[stw]|amg|as)?\d')
RE_DNS_STR4 = re.compile(r'^\|\|(al|anx|ao|apm|ar|at|au|asg?|axp?)[-\.]')
RE_DNS_STR5 = re.compile(r'^\|\|[a-z][a-z]?\d')
# URL 开头
RE_URL = re.compile(r'^\$|^\*|^%')
# $ 修饰 规则
RE_NoS = re.compile(r'\$')
# CSS 和 $$ 规则
RE_CSS = re.compile(r'#|\$\$')

def fetch_content(url):
    try:
        print(f"Fetching: {url}")
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        return resp.text.splitlines()
    except Exception as e:
        print(f"Error fetching {url}: {e}")
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
                # 仅保留的顶级域名为 cn, com, org, net，去除不常用域名
                if not RE_DNS_TLD.match(line) or RE_DNS_SEC1.match(line) or RE_DNS_SEC2.match(line) or RE_DNS_UCM1.search(line) or RE_DNS_UCM2.search(line):
                    continue
                # 去除某些域名开头
                if RE_DNS_STR1.match(line) or RE_DNS_STR2.match(line) or RE_DNS_STR3.match(line) or RE_DNS_STR4.match(line) or RE_DNS_STR5.match(line):
                    continue
                # 保留其他规则
                filtered.add(line_lower)
        
        elif rule_type in ["ads_pro", "prv_pro"]:
            # 去除 CSS 和纯域名规则
            if RE_CSS.search(line) or RE_DNS.match(line):
                continue
            # 保留其他规则
            filtered.add(line_lower)
        
        elif rule_type in ["ads", "prv"]:
            # 去除 CSS 和纯域名规则
            if RE_CSS.search(line) or RE_DNS.match(line):
                continue
            # 去除 $ 规则
            if RE_NoS.search(line) or RE_URL.match(line):
                continue
            # 保留其他规则
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
        print("No changes to commit.")
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
        print(f"Processing category: {category}")
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