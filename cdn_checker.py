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

def get_cloudflare_cidr():
    """从 Cloudflare 页面获取 IPv4 CIDR 列表。"""
    url = "https://www.cloudflare.com/ips-v4/"
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.text.splitlines()
    except requests.exceptions.RequestException as e:
        print(f"获取 Cloudflare IP 列表失败: {e}")
        return []

def is_cloudflare_ip(ip, cidr_list):
    """检查 IP 是否在 Cloudflare 的 CIDR 列表中。"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        for cidr in cidr_list:
            if ip_obj in ipaddress.ip_network(cidr, strict=False):
                return True
    except ValueError:
      
        return False  # ip格式错误直接跳过
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

def check_domain(domain, cidr_list):
    """检查单个域名是否使用了 Cloudflare CDN。"""
    try:
        ips = resolve_domain(domain)
        for ip in ips:
            if is_cloudflare_ip(ip, cidr_list):
                return True
    except Exception:
        return False
    return False

def process_domain(args):
    """处理单个域名并返回是否使用 Cloudflare 和记录字符串"""
    domain, cidr_list = args
    if check_domain(domain, cidr_list):
      return domain
    return None

def init_worker(cloudflare_cidr):
    global cidr_list_worker
    cidr_list_worker = cloudflare_cidr

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
    # 在主函数开始时增加文件限制
    increase_file_limit()
    
    cloudflare_cidr = get_cloudflare_cidr()
    if not cloudflare_cidr:
        return

    # 先测试 cloudflare.com
    if check_domain("cloudflare.com", cloudflare_cidr):
        print("cloudflare.com 检测通过", flush=True)
    else:
        print("cloudflare.com 检测失败，请检查网络", flush=True)
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
    
    cloudflare_domains = []
    total_domains = len(domains)
    processed = 0
    matched_count = 0  # 添加匹配计数器
    last_update_time = time.time()  # 添加时间记录
    
    print(f"开始处理 {total_domains} 个域名...", flush=True)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=512) as executor:
        futures = []
        results = []
        
        # 提交任务
        for domain in domains:
            future = executor.submit(process_domain, (domain, cloudflare_cidr))
            futures.append(future)
        
        # 获取结果
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result:
                    results.append(result)
                    matched_count += 1  # 更新匹配计数
                processed += 1
                if processed % 10000 == 0:  # 每处理10000个域名打印一次进度
                    percentage = (processed / total_domains) * 100
                    # 如果有匹配结果，随机选择一个显示
                    random_domain = random.choice(results) if results else None
                    status = format_status(last_update_time, matched_count, random_domain)
                    print(
                        f"进度: {processed}/{total_domains} "
                        f"({percentage:.1f}%) | {status}",
                        flush=True
                    )
                    last_update_time = time.time()  # 更新时间记录
            except Exception as e:
                print(f"无法处理: {e}", flush=True)
        
        cloudflare_domains = results
    
    with open('cloudflare_doamins.txt', 'w', encoding='utf-8') as f:
        #print("\n发现的 Cloudflare 域名：")
        for domain in cloudflare_domains:
            f.write(f"domain:{domain}\n") 
            #print(domain)
    
    print("\n处理完成，结果已保存在 cloudflare_doamins.txt", flush=True)

if __name__ == "__main__":
    main()
