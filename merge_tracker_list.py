import re

import requests


def download_trackerslist():
    all_trackers_list = ""

    res = requests.get('https://cf.trackerslist.com/all.txt')
    if res.status_code == 200:
        all_trackers_list = all_trackers_list + "\n" + res.text

    res = requests.get('https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all.txt')
    if res.status_code == 200:
        all_trackers_list = all_trackers_list + "\n" + res.text

    res = requests.get('https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all_ip.txt')
    if res.status_code == 200:
        all_trackers_list = all_trackers_list + "\n" + res.text

    res = requests.get('https://down.adysec.com/trackers_all.txt')
    if res.status_code == 200:
        all_trackers_list = all_trackers_list + "\n" + res.text

    res = requests.get(
        'https://raw.githubusercontent.com/hezhijie0327/Trackerslist/refs/heads/main/trackerslist_combine.txt')
    if res.status_code == 200:
        all_trackers_list = all_trackers_list + "\n" + res.text

    res = requests.get(
        'https://newtrackon.com/api/stable?include_ipv4_only_trackers=1&include_ipv6_only_trackers=1&min_age_days=0')
    if res.status_code == 200:
        all_trackers_list = all_trackers_list + "\n" + res.text

    res = requests.get('https://torrends.to/torrent-tracker-list/?download=latest')
    if res.status_code == 200:
        all_trackers_list = all_trackers_list + "\n" + res.text

    res = requests.get('https://www.justdailytrackers.com/trackers.js')
    if res.status_code == 200:
        pattern = r'const\s+(?P<var_name>\w+)\s*=\s*`(?P<content>.*?)`'
        matches = re.finditer(pattern, res.text, re.DOTALL)
        extracted_data = {}
        for match in matches:
            var_name = match.group('var_name')
            raw_text = match.group('content')
            clean_lines = dict.fromkeys([
                line.strip() for line in raw_text.splitlines() if line.strip()
            ])
            formatted_text = "\n\n".join(clean_lines)
            extracted_data[var_name] = formatted_text
        all_trackers_list = all_trackers_list + "\n" + extracted_data['allTrackers']

    with open('all_trackers_list.txt', 'w', encoding="utf-8") as f:
        clean_lines = dict.fromkeys(
            [line.strip() for line in all_trackers_list.splitlines() if line.strip()]
        )
        final_text = "\n\n".join(clean_lines) + "\n\n"
        f.write(final_text)
        print(f"成功生成去重文件")


def download_bset_trackerslist():
    all_trackers_list = ""

    res = requests.get('https://cf.trackerslist.com/best.txt')
    if res.status_code == 200:
        all_trackers_list = all_trackers_list + "\n" + res.text

    res = requests.get('https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_best.txt')
    if res.status_code == 200:
        all_trackers_list = all_trackers_list + "\n" + res.text

    res = requests.get('https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_best_ip.txt')
    if res.status_code == 200:
        all_trackers_list = all_trackers_list + "\n" + res.text

    res = requests.get('https://down.adysec.com/trackers_best.txt')
    if res.status_code == 200:
        all_trackers_list = all_trackers_list + "\n" + res.text

    res = requests.get(
        'https://raw.githubusercontent.com/hezhijie0327/Trackerslist/refs/heads/main/trackerslist_tracker.txt')
    if res.status_code == 200:
        all_trackers_list = all_trackers_list + "\n" + res.text

    res = requests.get(
        'https://newtrackon.com/api/stable?include_ipv4_only_trackers=1&include_ipv6_only_trackers=1&min_age_days=0')
    if res.status_code == 200:
        all_trackers_list = all_trackers_list + "\n" + res.text

    res = requests.get('https://torrends.to/torrent-tracker-list/?download=latest')
    if res.status_code == 200:
        all_trackers_list = all_trackers_list + "\n" + res.text

    res = requests.get('https://www.justdailytrackers.com/trackers.js')
    if res.status_code == 200:
        pattern = r'const\s+(?P<var_name>\w+)\s*=\s*`(?P<content>.*?)`'
        matches = re.finditer(pattern, res.text, re.DOTALL)
        extracted_data = {}
        for match in matches:
            var_name = match.group('var_name')
            raw_text = match.group('content')
            clean_lines = dict.fromkeys([
                line.strip() for line in raw_text.splitlines() if line.strip()
            ])
            formatted_text = "\n\n".join(clean_lines)
            extracted_data[var_name] = formatted_text
        all_trackers_list = all_trackers_list + "\n" + extracted_data['bestTrackers']

    with open('best_trackers_list.txt', 'w', encoding="utf-8") as f:
        clean_lines = dict.fromkeys(
            [line.strip() for line in all_trackers_list.splitlines() if line.strip()]
        )
        final_text = "\n\n".join(clean_lines) + "\n\n"
        f.write(final_text)
        print(f"成功生成去重文件")


if __name__ == '__main__':
    download_trackerslist()
    download_bset_trackerslist()
