import csv
import requests
import ipaddress
import multiprocessing
from multiprocessing import Pool
import socket
from colorama import init, Fore, Style
from tqdm import tqdm
import random
import concurrent.futures
import dns.resolver
from itertools import cycle

init(autoreset=True)  # 初始化 colorama，autoreset=True 自动重置颜色

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
    
def main():
    cloudflare_cidr = get_cloudflare_cidr()
    if not cloudflare_cidr:
      return

    # 先测试 cloudflare.com
    if check_domain("cloudflare.com",cloudflare_cidr):
        print("cloudflare.com 检测通过")
    else:
        print("cloudflare.com 检测失败，请检查网络")
        return
    
    cloudflare_domains = []
    
    with open("100k.csv", 'r', encoding='utf-8') as file:
            csv_reader = csv.reader(file)
            next(csv_reader, None)  # skip the header
            domains = [row[0] for row in csv_reader]
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=128) as executor:
        futures = []
        results = []
        
        # 使用tqdm包装任务提交过程
        with tqdm(total=len(domains), desc="Submitting tasks", ncols=80) as submit_pbar:
            for domain in domains:
                future = executor.submit(process_domain, (domain, cloudflare_cidr))
                futures.append(future)
                submit_pbar.update(1)
                
        # 使用tqdm包装结果获取过程    
        with tqdm(total=len(futures), desc="Processing domains", ncols=80) as pbar:
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                except Exception as e:
                    print(f"\nError processing domain: {e}")
                pbar.update(1)
        
        cloudflare_domains = results
    
    with open('cloudflare_doamins.txt', 'w', encoding='utf-8') as f:
        for domain in cloudflare_domains:
            f.write(domain + '\n')
            print(Fore.GREEN + domain)
    
    print(Fore.YELLOW + "处理完成，结果保存在 cloudflare_doamins.txt")
    

if __name__ == "__main__":
    main()
