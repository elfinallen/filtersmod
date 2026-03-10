import os
import re
import requests
import subprocess
from datetime import datetime

# 配置链接
SUPPLE_DNS = "https://raw.githubusercontent.com/elfinallen/filters/main/ublockd.txt"
ADGUARD_DNS = "https://raw.githubusercontent.com/elfinallen/filtersmod/main/adgdns.txt"
OUTPUT_FILE = "duplicate.txt"

# Git 配置
GIT_USER_NAME = "GitHub Action"
GIT_USER_EMAIL = "action@github.com"
COMMIT_MESSAGE = "chore: auto-update duplicate rules [skip ci]"

def fetch_content(url):
    """获取远程文件内容"""
    print(f"Fetching {url}...")
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        return response.text
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return None

def extract_domain_from_rule(rule):
    """
    从 ABP 规则中提取纯域名。
    只处理 ||domain^ 格式，排除包含路径 (/) 或修饰符 ($) 的规则。
    """
    rule = rule.strip()
    match = re.match(r'^\|\|[^/]+\^$', rule)
    if match:
        return match.group(1)
    return None

def parse_pure_domain_rules(content):
    """
    解析文件内容，返回纯域名规则的字典：{domain: original_rule}
    """
    rules_map = {}
    if not content:
        return rules_map
        
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('!') or line.startswith('['):
            continue
        domain = extract_domain_from_rule(line)
        if domain:
            if domain not in rules_map:
                rules_map[domain] = line
    return rules_map

def run_git_command(command):
    """运行 git 命令"""
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Git command failed: {e}")
        print(f"stderr: {e.stderr}")
        return None

def git_commit_and_push():
    """配置 Git 并提交推送"""
    print("Configuring Git...")
    run_git_command(f'git config --local user.name "{GIT_USER_NAME}"')
    run_git_command(f'git config --local user.email "{GIT_USER_EMAIL}"')
    
    print("Checking for changes...")
    # 检查文件是否有变动
    status = run_git_command(f'git status --porcelain {OUTPUT_FILE}')
    
    if not status or len(status) == 0:
        print("No changes to commit.")
        return False
    
    print("Changes detected, committing...")
    run_git_command(f'git add {OUTPUT_FILE}')
    run_git_command(f'git commit -m "{COMMIT_MESSAGE}"')
    
    print("Pushing to remote...")
    run_git_command('git push')
    
    print("Successfully committed and pushed!")
    return True

def main():
    # 1. 获取内容
    supple_content = fetch_content(SUPPLE_DNS)
    adguard_content = fetch_content(ADGUARD_DNS)

    if not supple_content or not adguard_content:
        print("Failed to fetch one of the lists. Exiting.")
        return False

    # 2. 解析规则
    print("Parsing EasyList China...")
    supple_domains = parse_pure_domain_rules(supple_content)
    
    print("Parsing AdGuard DNS Filter...")
    adguard_domains = set(parse_pure_domain_rules(adguard_content).keys())

    # 3. 对比找出重复
    print("Comparing rules...")
    duplicates = []
    for domain, rule in supple_domains.items():
        if domain in adguard_domains:
            duplicates.append(rule)
    
    # 4. 排序并写入文件
    duplicates.sort()
    
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write(f"! Generated at {datetime.utcnow().isoformat()}\n")
        f.write(f"! Total duplicates: {len(duplicates)}\n")
        for rule in duplicates:
            f.write(f"{rule}\n")
    
    print(f"Finished. Found {len(duplicates)} duplicates. Saved to {OUTPUT_FILE}")
    
    # 5. Git 提交和推送
    git_commit_and_push()
    
    return True

if __name__ == "__main__":
    main()