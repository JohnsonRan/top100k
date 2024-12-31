import csv
import requests
import ipaddress
import multiprocessing
from multiprocessing import Pool
import socket
import random
import concurrent.futures
import dns.resolver
from itertools import cycle
import psutil
import time
import resource
from datetime import datetime
import sys

# 添加DNS服务器列表
DNS_SERVERS = [
    '1.1.1.1',        # Cloudflare
    '8.8.8.8',        # Google
    '208.67.222.222', # OpenDNS
    '9.9.9.9',        # Quad9
    '114.114.114.114' # 114DNS
]

# 定义CDN提供商配置
CDN_PROVIDERS = {
    'cloudflare': {
        'name': 'Cloudflare',
        'url': 'https://www.cloudflare.com/ips-v4/'
    },
    'akamai': {
        'name': 'Akamai', 
        'url': 'https://github.com/MetaCubeX/meta-rules-dat/raw/meta/asn/AS20940.list'
    },
    'fastly': {
        'name': 'Fastly',
        'url': 'https://github.com/MetaCubeX/meta-rules-dat/raw/meta/asn/AS54113.list'
    },
    'cloudfront': {
        'name': 'Cloudfront/Vercel',
        'url': 'https://github.com/MetaCubeX/meta-rules-dat/raw/meta/asn/AS16509.list'
    },
    'gcore': {
        'name': 'GCore',
        'url': 'https://github.com/MetaCubeX/meta-rules-dat/raw/meta/asn/AS199524.list'
    }
}

def get_ip_list(provider_config):
    """获取CDN提供商的CIDR列表"""
    try:
        response = requests.get(provider_config['url'])
        response.raise_for_status()
        return [line.strip() for line in response.text.splitlines() if line.strip()]
    except requests.exceptions.RequestException as e:
        print(f"获取 {provider_config['name']} IP 列表失败: {e}")
        return []

def is_ip_in_list(ip, cidr_list):
    """检查IP是否在CIDR列表中"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        for cidr in cidr_list:
            if ip_obj in ipaddress.ip_network(cidr, strict=False):
                return True
    except ValueError:
        return False
    return False

def resolve_domain(domain):
    """使用多个DNS服务器解析域名"""
    dns_server = random.choice(DNS_SERVERS)
    resolver = dns.resolver.Resolver(configure=False)  # 禁用系统DNS配置
    resolver.timeout = 2
    resolver.lifetime = 2
    resolver.nameservers = [dns_server]
    
    try:
        answers = resolver.resolve(domain, 'A')
        return [rdata.address for rdata in answers]
    except Exception as e:
        #print(f"DNS解析错误 ({dns_server}): {domain} - {e}")  # 可选的调试信息
        return []

def check_domain(domain, cdn_ip_lists):
    """检查单个域名是否使用了任何CDN"""
    try:
        ips = resolve_domain(domain)
        results = {}
        for provider, ip_list in cdn_ip_lists.items():
            for ip in ips:
                if is_ip_in_list(ip, ip_list):
                    results[provider] = True
                    break
        return results
    except Exception:
        return {}

def process_domain(args):
    """处理单个域名并返回CDN使用情况"""
    domain, cdn_ip_lists = args
    results = check_domain(domain, cdn_ip_lists)
    if results:
        return domain, results
    return None

def format_status(last_time, matched_count, random_domain=None):
    """格式化状态信息，包含内存使用、耗时、匹配数量和随机域名示例"""
    process = psutil.Process()
    memory_mb = process.memory_info().rss / 1024 / 1024
    elapsed = time.time() - last_time
    status = f"内存: {memory_mb:.1f}MB | 耗时: {elapsed:.1f}秒 | 已匹配: {matched_count}个"
    if random_domain and matched_count > 0:
        status += f" | {random_domain}"
    return status

def increase_file_limit():
    """增加文件描述符限制"""
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))
        print(f"文件描述符限制已设置为: {hard}")
    except Exception as e:
        print(f"设置文件描述符限制失败: {e}")

def download_ad_rules():
    """下载广告规则文件"""
    sources = {
        'adrules': {
            'url': "https://adrules.top/adrules_domainset.txt",
            'prefix': '+.',
            'file': 'adrules_domainset.txt'
        },
        'hagezi': {
            'url': "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/multi.txt",
            'prefix': '*.',
            'file': 'multi.txt'
        },
        'skk': {
            'url': "https://ruleset.skk.moe/Clash/domainset/reject_extra.txt",
            'prefix': '+.',
            'file': 'reject_extra.txt'
        }
    }
    
    success = True
    for name, source in sources.items():
        try:
            print(f"正在下载 {name} 规则文件...")
            response = requests.get(source['url'])
            response.raise_for_status()
            
            with open(source['file'], 'w', encoding='utf-8') as f:
                f.write(response.text)
            print(f"{name} 规则文件下载完成")
        except Exception as e:
            print(f"下载 {name} 规则文件失败: {e}")
            success = False
    
    return success

def load_ad_domains():
    """加载广告域名列表并处理"""
    # 先尝试下载最新的规则文件
    download_ad_rules()
    
    ad_domains = set()
    files = [
        ('adrules_domainset.txt', '+.'),
        ('multi.txt', '*.'),
        ('reject_extra.txt', '+.')
    ]
    
    for filename, prefix in files:
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                for line in f:
                    # 移除开头的前缀（+. 或 *.）并清理空白字符
                    domain = line.strip().lstrip(prefix)
                    if domain:
                        ad_domains.add(domain)
            print(f"已加载 {filename} 规则文件")
        except FileNotFoundError:
            print(f"警告: {filename} 文件不存在")
    
    print(f"总计加载 {len(ad_domains)} 个广告域名规则")
    return ad_domains

def filter_domains(domains, ad_domains):
    """过滤掉广告域名"""
    filtered = [d for d in domains if d not in ad_domains]
    return filtered

def main():
    increase_file_limit()
    
    # 获取所有CDN提供商的IP列表
    cdn_ip_lists = {}
    for provider_id, config in CDN_PROVIDERS.items():
        ip_list = get_ip_list(config)
        if ip_list:
            cdn_ip_lists[provider_id] = ip_list
            print(f"已加载 {config['name']} IP列表：{len(ip_list)}条")
    
    if not cdn_ip_lists:
        print("无法获取任何CDN提供商的IP列表")
        return
    
    # 加载广告域名
    ad_domains = load_ad_domains()
    
    # 读取并过滤域名
    domains = []
    with open("100k.csv", 'r', encoding='utf-8') as file:
        csv_reader = csv.reader(file)
        next(csv_reader, None)  # skip the header
        domains = [row[0] for row in csv_reader]
    
    original_count = len(domains)
    print(f"原始域名数量: {original_count}", flush=True)
    
    # 过滤广告域名
    domains = filter_domains(domains, ad_domains)
    filtered_count = len(domains)
    print(f"过滤后域名数量: {filtered_count}", flush=True)
    print(f"已过滤掉 {original_count - filtered_count} 个广告域名", flush=True)
    
    results = {}
    processed = 0
    last_update_time = time.time()
    
    print(f"开始处理 {filtered_count} 个域名...", flush=True)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=512) as executor:
        futures = []
        
        for domain in domains:
            future = executor.submit(process_domain, (domain, cdn_ip_lists))
            futures.append(future)
        
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result:
                    domain, cdn_results = result
                    results[domain] = cdn_results
                processed += 1
                if processed % 10000 == 0:
                    percentage = (processed / filtered_count) * 100
                    status = format_status(last_update_time, len(results))
                    print(f"进度: {processed}/{filtered_count} ({percentage:.1f}%) | {status}", flush=True)
                    last_update_time = time.time()
            except Exception as e:
                print(f"无法处理: {e}", flush=True)
    
    # 保存每个CDN提供商的域名到单独文件
    for provider_id, config in CDN_PROVIDERS.items():
        with open(f'{provider_id}_domains.txt', 'w', encoding='utf-8') as f:
            for domain, cdn_results in results.items():
                if cdn_results.get(provider_id):
                    f.write(f"domain:{domain}\n")
    
    # 保存所有使用任何CDN的域名到合集文件
    with open('all_cdn_domains.txt', 'w', encoding='utf-8') as f:
        # 使用集合去重
        cdn_domains = set(domain for domain, cdn_results in results.items() if cdn_results)
        for domain in cdn_domains:
            f.write(f"domain:{domain}\n")
    
    print("\n处理完成，结果已保存")
    print(f"所有CDN域名已保存到 all_cdn_domains.txt")
    for provider_id, config in CDN_PROVIDERS.items():
        provider_domains = sum(1 for r in results.values() if r.get(provider_id))
        print(f"{config['name']}: {provider_domains}个域名 (已保存到 {provider_id}_domains.txt)")

if __name__ == "__main__":
    main()
