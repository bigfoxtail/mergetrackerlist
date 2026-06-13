import requests


def download_trackerslist():
    all_trackers_list = ""
    res = requests.get('https://cf.trackerslist.com/all.txt')
    if res.status_code == 200:
        all_trackers_list = all_trackers_list + "\n" + res.text
    res = requests.get('https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all.txt')
    if res.status_code == 200:
        all_trackers_list = all_trackers_list + "\n" + res.text
    res = requests.get('https://torrends.to/torrent-tracker-list/?download=latest')
    if res.status_code == 200:
        all_trackers_list = all_trackers_list + "\n" + res.text
    res = requests.get('https://www.justdailytrackers.com/tracker-snapshots.json')
    if res.status_code == 200:
        tracker_json = res.json()
        for tracker_info in tracker_json["items"]:
            all_trackers_list = all_trackers_list + "\n" + tracker_info['url']
    with open('all_trackers_list.txt', 'w', encoding="utf-8") as f:
        clean_lines = dict.fromkeys(
            [line.strip() for line in all_trackers_list.splitlines() if line.strip()]
        )
        final_text = "\n\n".join(clean_lines) + "\n\n"
        f.write(final_text)
        print(f"成功生成去重文件")


if __name__ == '__main__':
    download_trackerslist()
