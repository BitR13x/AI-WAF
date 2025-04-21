import requests
from utils import relative_path
import os

def download_file(save_dir: str, url: str) -> None:
    """ Downloads a file from the specified URL and saves it to the given directory """
    response = requests.get(url)
    filename = url.split("/")[-1]
    file_path = relative_path(os.path.join(save_dir, filename))

    # possible improvement: check: hash or last line
    if response.status_code == 200:
        if os.path.isfile(file_path):
            with open(file_path, 'r+') as file:
                old_content = file.read()
                if old_content != response.text:
                    file.seek(0)
                    file.write(response.text)
                    file.truncate()
        else:
            with open(file_path, "w") as file:
                file.write(response.text)

        print(f"Downloaded and saved: {file_path}")
    else:
        print(f"Failed to download file: {url} (Status code: {response.status_code})")

if __name__ == "__main__":
    file_list = ["https://rules.emergingthreats.net/blockrules/compromised-ips.txt"]
    for url in file_list:
        download_file("rules/blacklist", url)

# crontab rule to execute every week:
# 0 0 * * 0 /usr/bin/python /path/to/your/script.py