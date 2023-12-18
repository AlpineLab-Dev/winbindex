import json
import re
import requests

def main():
    with open("diff_data.json", "r") as f:
        data = json.load(f)

    while True:
        key = input("Input> ")

        if data.get(key):
            for v in data[key].values():
                if not v.get("link"):
                    print("No link...")
                    continue

            for v in data[key].values():
                name = v["kb"][0] + "_" + key
                with open(name, "wb") as f:
                    f.write(requests.get(v['link']).content)

        else:
            p = re.compile(f"^{key}")

            for k in data.keys():
                if p.match(k):
                    print(k)
            print()

if __name__ == "__main__":
    main()