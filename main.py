import pandas as pd
import re
import concurrent.futures
import os
import json
import requests
import yaml
import ipaddress
from io import StringIO

# 映射字典
MAP_DICT = {'DOMAIN-SUFFIX': 'domain_suffix', 'HOST-SUFFIX': 'domain_suffix', 'host-suffix': 'domain_suffix', 'DOMAIN': 'domain', 'HOST': 'domain', 'host': 'domain',
            'DOMAIN-KEYWORD':'domain_keyword', 'HOST-KEYWORD': 'domain_keyword', 'host-keyword': 'domain_keyword', 'IP-CIDR': 'ip_cidr',
            'ip-cidr': 'ip_cidr', 'IP-CIDR6': 'ip_cidr', 
            'IP6-CIDR': 'ip_cidr','SRC-IP-CIDR': 'source_ip_cidr', 'GEOIP': 'geoip', 'DST-PORT': 'port',
            'SRC-PORT': 'source_port', "URL-REGEX": "domain_regex", "DOMAIN-REGEX": "domain_regex"}

# 定义分类字段
DOMAIN_FIELDS = {'domain', 'domain_suffix', 'domain_keyword', 'domain_regex'}
IP_FIELDS = {'ip_cidr', 'source_ip_cidr', 'geoip'}
# 注意：port 和 source_port 不在上述集合中，会自动被忽略

def read_yaml_from_url(url):
    headers = {'User-Agent': 'Mozilla/5.0'}
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    yaml_data = yaml.safe_load(response.text)
    return yaml_data

def read_list_from_url(url):
    headers = {'User-Agent': 'Mozilla/5.0'}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        csv_data = StringIO(response.text)
        df = pd.read_csv(csv_data, header=None, names=['pattern', 'address', 'other', 'other2', 'other3'], on_bad_lines='skip')
    else:
        return None
    filtered_rows = []
    rules = []
    # 处理逻辑规则 (保持原样，默认不输出逻辑规则)
    if 'AND' in df['pattern'].values:
        and_rows = df[df['pattern'].str.contains('AND', na=False)]
        for _, row in and_rows.iterrows():
            rule = {
                "type": "logical",
                "mode": "and",
                "rules": []
            }
            pattern = ",".join(row.values.astype(str))
            components = re.findall(r'\((.*?)\)', pattern)
            for component in components:
                for keyword in MAP_DICT.keys():
                    if keyword in component:
                        match = re.search(f'{keyword},(.*)', component)
                        if match:
                            value = match.group(1)
                            rule["rules"].append({
                                MAP_DICT[keyword]: value
                            })
            rules.append(rule)
    for index, row in df.iterrows():
        if 'AND' not in row['pattern']:
            filtered_rows.append(row)
    df_filtered = pd.DataFrame(filtered_rows, columns=['pattern', 'address', 'other', 'other2', 'other3'])
    return df_filtered, rules

def is_ipv4_or_ipv6(address):
    try:
        ipaddress.IPv4Network(address)
        return 'ipv4'
    except ValueError:
        try:
            ipaddress.IPv6Network(address)
            return 'ipv6'
        except ValueError:
            return None

def parse_and_convert_to_dataframe(link):
    rules = []
    if link.endswith('.yaml') or link.endswith('.txt'):
        try:
            yaml_data = read_yaml_from_url(link)
            rows = []
            if not isinstance(yaml_data, str):
                items = yaml_data.get('payload', [])
            else:
                lines = yaml_data.splitlines()
                line_content = lines[0]
                items = line_content.split()
            for item in items:
                address = item.strip("'")
                if ',' not in item:
                    if is_ipv4_or_ipv6(item):
                        pattern = 'IP-CIDR'
                    else:
                        if address.startswith('+') or address.startswith('.'):
                            pattern = 'DOMAIN-SUFFIX'
                            address = address[1:]
                            if address.startswith('.'):
                                address = address[1:]
                        else:
                            pattern = 'DOMAIN'
                else:
                    pattern, address = item.split(',', 1)
                if ',' in address:
                    address = address.split(',', 1)[0]
                rows.append({'pattern': pattern.strip(), 'address': address.strip(), 'other': None})
            df = pd.DataFrame(rows, columns=['pattern', 'address', 'other'])
        except:
            df, rules = read_list_from_url(link)
    else:
        df, rules = read_list_from_url(link)
    return df, rules

def sort_dict(obj):
    if isinstance(obj, dict):
        return {k: sort_dict(obj[k]) for k in sorted(obj)}
    elif isinstance(obj, list) and all(isinstance(elem, dict) for elem in obj):
        return sorted([sort_dict(x) for x in obj], key=lambda d: sorted(d.keys())[0])
    elif isinstance(obj, list):
        return sorted(sort_dict(x) for x in obj)
    else:
        return obj

def build_and_compile_srs(base_name, output_directory, rule_type, df_grouped):
    """根据分类数据生成 JSON 并编译为 SRS，最后清理 JSON"""
    if not df_grouped:
        return None

    result_rules = {"version": 2, "rules": []}
    domain_entries = []

    for pattern, addresses in df_grouped.items():
        if pattern == 'domain_suffix':
            rule_entry = {pattern: [address.strip() for address in addresses]}
            result_rules["rules"].append(rule_entry)
        elif pattern == 'domain':
            domain_entries.extend([address.strip() for address in addresses])
        else:
            rule_entry = {pattern: [address.strip() for address in addresses]}
            result_rules["rules"].append(rule_entry)
            
    domain_entries = list(set(domain_entries))
    if domain_entries:
        result_rules["rules"].insert(0, {'domain': domain_entries})

    # 临时 json
    file_name = os.path.join(output_directory, f"{base_name}_{rule_type}.json")
    with open(file_name, 'w', encoding='utf-8') as output_file:
        result_rules_str = json.dumps(sort_dict(result_rules), ensure_ascii=False, indent=2)
        result_rules_str = result_rules_str.replace('\\\\', '\\')
        output_file.write(result_rules_str)

    # 编译 srs
    srs_path = file_name.replace(".json", ".srs")
    os.system(f"sing-box rule-set compile --output {srs_path} {file_name}")
    
    # 删除临时 json
    if os.path.exists(file_name):
        os.remove(file_name)
        
    return srs_path

def parse_list_file(link, output_directory):
    try:
        with concurrent.futures.ThreadPoolExecutor() as executor:
            results= list(executor.map(parse_and_convert_to_dataframe, [link]))
            dfs = [df for df, rules in results]
            rules_list = [rules for df, rules in results]
            df = pd.concat(dfs, ignore_index=True)
            
        df = df[~df['pattern'].str.contains('#')].reset_index(drop=True)
        df = df[df['pattern'].isin(MAP_DICT.keys())].reset_index(drop=True)
        df = df.drop_duplicates().reset_index(drop=True)
        df['pattern'] = df['pattern'].replace(MAP_DICT)
        os.makedirs(output_directory, exist_ok=True)

        # 获取基础文件名，保留大小写（如 Apple.yaml -> Apple）
        base_name = os.path.basename(link).split('.')[0]

        # 提取域名数据和 IP 数据（自动过滤掉 port 等不需要的数据）
        domain_df = df[df['pattern'].isin(DOMAIN_FIELDS)]
        ip_df = df[df['pattern'].isin(IP_FIELDS)]

        domain_grouped = domain_df.groupby('pattern')['address'].apply(list).to_dict()
        ip_grouped = ip_df.groupby('pattern')['address'].apply(list).to_dict()

        generated_files = []

        # 域名 srs
        domain_srs = build_and_compile_srs(base_name, output_directory, "domain", domain_grouped)
        if domain_srs:
            generated_files.append(domain_srs)

        # IP srs
        ip_srs = build_and_compile_srs(base_name, output_directory, "ip", ip_grouped)
        if ip_srs:
            generated_files.append(ip_srs)

        return generated_files
    except Exception as e:
        print(f'获取链接出错，已跳过：{link}，原因：{str(e)}')
        return []

if __name__ == "__main__":
    with open("../links.txt", 'r') as links_file:
        links = links_file.read().splitlines()

    links = [l for l in links if l.strip() and not l.strip().startswith("#")]

    output_dir = "./"
    all_result_files = []

    for link in links:
        result_files = parse_list_file(link, output_directory=output_dir)
        all_result_files.extend(result_files)

    for file_name in all_result_files:
        print(f"成功生成: {file_name}")