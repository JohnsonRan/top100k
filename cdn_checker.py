import csv
import requests
import ipaddress
import multiprocessing
from multiprocessing import Pool
import socket
import random
import concurrent.futures
import dns.resolver
import psutil
import time
import resource
from datetime import datetime
import sys
import threading
import bisect
import json

class DNSCache:
    def __init__(self, ttl=3600):
        self.cache = {}
        self.ttl = ttl
        self._lock = threading.Lock()

    def get(self, domain):
        with self._lock:
            if domain in self.cache:
                timestamp, ips = self.cache[domain]
                if time.time() - timestamp < self.ttl:
                    return ips
                del self.cache[domain]
            return None

    def set(self, domain, ips):
        with self._lock:
            self.cache[domain] = (time.time(), ips)

class IPRangeManager:
    def __init__(self):
        self.ranges = []  # [(start_ip, end_ip), ...]
        self._lock = threading.Lock()

    def add_range(self, start_ip, end_ip):
        with self._lock:
            bisect.insort(self.ranges, (start_ip, end_ip))

    def merge_ranges(self):
        """合并重叠的IP范围"""
        if not self.ranges:
            return
        
        with self._lock:
            merged = []
            current_start, current_end = self.ranges[0]
            
            for start, end in self.ranges[1:]:
                if start <= current_end + 1:
                    current_end = max(current_end, end)
                else:
                    merged.append((current_start, current_end))
                    current_start, current_end = start, end
            
            merged.append((current_start, current_end))
            self.ranges = merged

    def contains(self, ip):
        """使用二分查找检查IP是否在范围内"""
        ip_int = int(ipaddress.ip_address(ip))
        idx = bisect.bisect_right(self.ranges, (ip_int, float('inf'))) - 1
        if idx >= 0:
            start, end = self.ranges[idx]
            return start <= ip_int <= end
        return False

def preprocess_cidr_list(provider_id, cidr_list):
    """预处理CIDR列表并保存为IP范围"""
    range_manager = IPRangeManager()
    
    for cidr in cidr_list:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            start_ip = int(network.network_address)
            end_ip = int(network.broadcast_address)
            range_manager.add_range(start_ip, end_ip)
        except ValueError:
            continue
    
    range_manager.merge_ranges()
    
    # 保存到文件
    filename = f'{provider_id}_ranges.json'
    with open(filename, 'w') as f:
        json.dump(range_manager.ranges, f)
    
    return range_manager

def load_ip_ranges(provider_id):
    """加载预处理的IP范围"""
    filename = f'{provider_id}_ranges.json'
    try:
        with open(filename, 'r') as f:
            ranges = json.load(f)
        manager = IPRangeManager()
        manager.ranges = ranges
        return manager
    except (FileNotFoundError, json.JSONDecodeError):
        return None

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

dns_cache = DNSCache()

def resolve_domain(domain):
    """使用缓存的DNS解析"""
    cached_ips = dns_cache.get(domain)
    if cached_ips:
        return cached_ips

    dns_server = random.choice(DNS_SERVERS)
    resolver = dns.resolver.Resolver(configure=False)
    resolver.timeout = 1
    resolver.lifetime = 1
    resolver.nameservers = [dns_server]
    
    try:
        answers = resolver.resolve(domain, 'A')
        ips = [rdata.address for rdata in answers]
        dns_cache.set(domain, ips)
        return ips
    except Exception:
        return []

def check_domain(domain, cdn_ranges):
    """检查单个域名是否使用了任何CDN"""
    try:
        ips = resolve_domain(domain)
        results = {}
        for provider, range_manager in cdn_ranges.items():
            for ip in ips:
                if range_manager.contains(ip):
                    results[provider] = True
                    break
        return results
    except Exception:
        return {}

def process_domain(args):
    """处理单个域名"""
    domain, cdn_ranges = args
    results = check_domain(domain, cdn_ranges)
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
    
    # 获取所有CDN提供商的IP列表并预处理
    cdn_ranges = {}
    for provider_id, config in CDN_PROVIDERS.items():
        # 尝试加载预处理的范围文件
        range_manager = load_ip_ranges(provider_id)
        
        if range_manager is None:
            # 如果没有预处理文件，则重新处理
            ip_list = get_ip_list(config)
            if ip_list:
                range_manager = preprocess_cidr_list(provider_id, ip_list)
                print(f"已预处理并保存 {config['name']} IP范围")
        
        if range_manager:
            cdn_ranges[provider_id] = range_manager
            print(f"已加载 {config['name']} IP范围：{len(range_manager.ranges)}条")
    
    if not cdn_ranges:
        print("无法获取任何CDN提供商的IP范围")
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
    
    # 使用更大的线程池
    with concurrent.futures.ThreadPoolExecutor(max_workers=1000) as executor:
        chunk_size = 1000  # 每次处理1000个域名
        for i in range(0, len(domains), chunk_size):
            chunk = domains[i:i + chunk_size]
            futures = []
            
            for domain in chunk:
                future = executor.submit(process_domain, (domain, cdn_ranges))
                futures.append(future)
            
            # 处理当前批次结果
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        domain, cdn_results = result
                        results[domain] = cdn_results
                    processed += 1
                    
                    if processed % 1000 == 0:
                        percentage = (processed / filtered_count) * 100
                        status = format_status(last_update_time, len(results))
                        print(f"进度: {processed}/{filtered_count} ({percentage:.1f}%) | {status}", flush=True)
                        last_update_time = time.time()
                except Exception as e:
                    print(f"处理错误: {e}", flush=True)
    
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
