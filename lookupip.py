# import csv
# import requests
# import time

# # 提取唯一IP并保持原始顺序
# unique_ips = []
# seen_ips = set()

# with open('messenger_tmp.csv', 'r') as f:
#     reader = csv.reader(f)
#     next(reader)  # 跳过标题行
#     for row in reader:
#         ip = row[4].strip()
#         if ip not in seen_ips:
#             seen_ips.add(ip)
#             unique_ips.append(ip)

# # 查询IP信息
# ip_city = {}
# for ip in unique_ips:
#     url = f'http://ipinfo.io/{ip}/json'
#     try:
#         # 添加自定义User-Agent并设置5秒超时
#         response = requests.get(
#             url,
#             headers={'User-Agent': 'python-requests/2.26.0'},
#             timeout=5
#         )
#         response.raise_for_status()
#         data = response.json()
#         ip_city[ip] = data.get('city', 'Unknown')
#     except Exception as e:
#         print(f"Error querying {ip}: {str(e)}")
#         ip_city[ip] = 'Unknown'
#     time.sleep(1)  # 遵守API速率限制

# # 写入结果文件
# with open('output.txt', 'w', newline='') as f:
#     writer = csv.writer(f)
#     writer.writerow(['IP', 'City'])
#     for ip in unique_ips:
#         writer.writerow([ip, ip_city.get(ip, 'Unknown')])

# print("处理完成，结果已保存到output.txt")

import csv

# 读取原始数据
with open('output.txt', 'r') as f:
    reader = csv.reader(f)
    header = next(reader)  # 读取标题行
    data = [row for row in reader]

# 按城市名称排序（不区分大小写）
sorted_data = sorted(data, key=lambda x: x[1].lower())

# 写入排序结果
with open('sorted_by_city.txt', 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(['IP', 'City'])
    writer.writerows(sorted_data)

print("排序完成，结果已保存到 sorted_by_city.txt")