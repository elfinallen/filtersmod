import re
import ipaddress
import requests
from collections import Counter
from datetime import datetime, timezone

SOURCES = {
    "dns": [
        "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdns.txt"
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
    "dns": "adbdns.txt",
    "ads": "adbads.txt",
    "prv": "adbprv.txt"
}

HEADERS = {
    "dns": [
        "! Title: Adblock Domain",
        "! Description: DNS Filter composed of multiple Filters, removed uncommon rules."
    ],
    "ads": [
        "! Title: Adblock Advert",
        "! Description: Ads Filter composed of AdGuard Base & Chinese Filter, removed uncommon rules."
    ],
    "prv": [
        "! Title: Adblock Privacy",
        "! Description: Privacy Filter composed of AdGuard tracking & EasyPrivacy, removed uncommon rules."
    ]
}

# 正则规则
# 纯域名规则 ||domain^
RE_DNS = re.compile(r'^\|\|.+\^$')
# URL规则
RE_URL1 = re.compile(r'^\|?[-=:%&?!@*.\w]')
RE_URL2 = re.compile(r'^/[\d\W_]')
RE_URL3 = re.compile(r'^/.+\/$')
# 修饰规则
RE_NoS = re.compile(r'#|\$')


def is_ip(domain):
    """判断域名部分是否为 IP 地址（IPv4 或 IPv6）"""
    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        return False


def get_sld(domain):
    """获取二级域名（最后两段），如 a.b.example.com -> example.com"""
    parts = domain.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain


def filter_dns_rules(lines):
    """DNS 规则两阶段过滤：去 IP + 删除 SLD 仅出现1次且层级>=3 的规则"""
    # 阶段1：收集所有合法 DNS 规则，转小写去重，剔除 IP
    candidates = set()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if not RE_DNS.match(line):
            continue
        domain = line[2:-1].lower()  # 去掉 || 和 ^
        if not domain:
            continue
        if is_ip(domain):
            continue
        candidates.add(domain)

    # 阶段2：统计每个 SLD 出现的规则条数
    sld_counter = Counter()
    for domain in candidates:
        sld_counter[get_sld(domain)] += 1

    # 阶段3：过滤 —— 层级>=3 且 SLD 计数==1 的删除
    filtered = set()
    for domain in candidates:
        level = domain.count(".") + 1
        if level >= 3 and sld_counter[get_sld(domain)] == 1:
            continue
        filtered.add(f"||{domain}^")

    return sorted(filtered)


def fetch_content(url):
    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        return resp.text.splitlines()
    except Exception as e:
        print(f"[WARN] fetch failed: {url} -> {e}")
        return []


def filter_rules(lines, rule_type):
    if rule_type == "dns":
        return filter_dns_rules(lines)

    filtered = set()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if RE_DNS.match(line) or RE_URL1.match(line) or RE_URL2.match(line) or RE_URL3.match(line) or RE_NoS.search(line):
            continue
        filtered.add(line.lower())

    return sorted(filtered)


def write_file(filename, header_lines, rules):
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    with open(filename, "w", encoding="utf-8") as f:
        for h in header_lines:
            f.write(f"{h}\n")
        f.write(f"! Last Updated: {timestamp}\n")
        f.write(f"! Total Rules: {len(rules)}\n")
        f.write(f"! Expires: 5 days\n")
        for rule in rules:
            f.write(f"{rule}\n")


def main():
    all_rules = {}

    for category, urls in SOURCES.items():
        merged_lines = []
        for url in urls:
            merged_lines.extend(fetch_content(url))

        all_rules[category] = filter_rules(merged_lines, category)

    for category, rules in all_rules.items():
        filename = OUTPUT_FILES[category]
        header = HEADERS[category]
        write_file(filename, header, rules)


if __name__ == "__main__":
    main()