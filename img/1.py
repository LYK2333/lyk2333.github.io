import os
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# 目标网页URL
url = 'https://xz.aliyun.com/t/12921?time__1311=GqGxuD9QKCqxlxx20DRYxcGERfE4muwmD&u_atoken=d0dcb88442bb47b1ba27c6b13c766eae&u_asession=01PTB81zfz48ib2hEJYiwZ2CfE0aHff6_IH2dTB16K5WGBeGoRW2e10n2jp4GkwoK7JB-YY_UqRErInTL5mMzm-GyPlBJUEqctiaTooWaXr7I&u_asig=05uxjJKNHNA1QNKWxNbnxLUuZJnguKfagfp8_UDc9trV-Q9_FZ6wre_CETxc0wnxHmAgAS7zGID515PyJQ5gLyQDhonVbeoFNRlQQ7brlEhO-X-6YP1L0m-viu4Y5xhUgcSysEObTEZ8Icxm0VBhre8Rvsckx16wjTSxwNNucIYy_BzhvSc0Kr8URjOX9Xe4tkbfU64DKytbGRcv4yBGXpCerUxQSyzvQc7vnJLR87yA2vZXz9BlS3rQO7SXeRLedCEdmBOLCQ21OBKztI4bm9qvnQIfMK6z51Dw1JaWHvZKN6gx6UxFgdF3ARCQ86jS_u_XR5hatHQVh06VuUZ-D1wA&u_aref=%2BryeOjR5wAIW50hacRjrzIhiYg0%3D'

# 创建保存图片的文件夹
os.makedirs('images', exist_ok=True)

# 获取网页内容
response = requests.get(url)
response.raise_for_status()  # 检查请求是否成功

# 使用BeautifulSoup解析网页
soup = BeautifulSoup(response.text, 'html.parser')

# 找到所有图片标签
img_tags = soup.find_all('img')

# 记录下载的图片数量
count = 0

# 下载每张图片
for img in img_tags:
    img_url = img.get('src')
    if not img_url:
        continue
    
    # 处理相对URL
    img_url = urljoin(url, img_url)
    
    # 获取图片数据
    img_response = requests.get(img_url)
    if img_response.status_code == 200:
        # 提取图片文件名
        img_name = os.path.join('images', os.path.basename(img_url))
        
        # 保存图片到本地
        with open(img_name, 'wb') as img_file:
            img_file.write(img_response.content)
        
        count += 1
        print(count)
    else:
        print(f"Failed to download {img_url}")

print(f"共下载了 {count} 张图片。")
