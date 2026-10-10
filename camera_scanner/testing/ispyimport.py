#!/usr/bin/env python3
"""
Парсит таблицу моделей камер с iSpyConnect для указанного бренда.

Использование:
    python ispyimport.py hikvision
    python ispyimport.py dahua --out db/
    python ispyimport.py axis --delay 2.0
"""

import argparse
import sys
import time
from pathlib import Path

import requests
import yaml
from bs4 import BeautifulSoup
import re

BASE = "https://www.ispyconnect.com"
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
}
REQUEST_DELAY = 1.5  # пауза между страницами одного бренда, сек


def build_url(protocol: str, port: str, path: str) -> str:
    url = protocol
    url += "{user}:{pass}@{ip}"
    if port and port != "0":
        url += f":{port}"
    if not path.startswith("/"):
        url += "/"
    url += path
    return url


def classify(path: str, protocol: str) -> str:
    p = path.lower()
    if protocol.startswith("rtsp") or "stream" in p or "live" in p or "h264" in p:
        return "stream"
    if any(k in p for k in ("snapshot", "picture", "jpg", "jpeg", "capture")):
        return "snapshot"
    if "ptz" in p or "pan" in p or "tilt" in p or "zoom" in p:
        return "ptz"
    if "mjpg" in p or "mjpeg" in p or "video.cgi" in p:
        return "stream"
    return "other"


def parse_page(html: str) -> dict:
    soup = BeautifulSoup(html, "html.parser")
    result = {}

    for row in soup.select("tr[data-conn]"):
        protocol = row.get("data-protocol", "")
        port = row.get("data-port", "")
        path = row.get("data-path", "")
        if not protocol or not path:
            continue

        url_template = build_url(protocol, port, path)
        kind = classify(path, protocol)

        for a in row.select("a.model-link"):
            model = a.get_text(strip=True)
            if not model:
                continue
            result.setdefault(model, {"snapshot": [], "stream": [], "ptz": [], "other": []})
            if url_template not in result[model][kind]:
                result[model][kind].append(url_template)

    return result


def fetch_all_pages(brand: str, session: requests.Session, delay: float) -> dict:
    all_models = {}
    page = 1
    while True:
        url = f"{BASE}/camera/{brand}?page={page}"
        print(f"  → {url}")
        try:
            r = session.get(url, headers=HEADERS, timeout=20)
            r.raise_for_status()
        except requests.RequestException as e:
            print(f"  ❌ Ошибка запроса: {e}")
            break

        page_models = parse_page(r.text)
        if not page_models:
            print(f"  Страница {page} пуста — останавливаемся")
            break

        for model, kinds in page_models.items():
            if model not in all_models:
                all_models[model] = kinds
            else:
                for k, urls in kinds.items():
                    for u in urls:
                        if u not in all_models[model][k]:
                            all_models[model][k].append(u)

        print(f"    +{len(page_models)} моделей (всего {len(all_models)})")

        soup = BeautifulSoup(r.text, "html.parser")
        pager = soup.select_one(".manPager")
        if not pager:
            break
        next_link = pager.find("a", string=re.compile(r"Next|→|»|next", re.I))
        if not next_link:
            break

        page += 1
        time.sleep(delay)

    return all_models


def main():
    parser = argparse.ArgumentParser(
        description="Парсит модели камер с iSpyConnect для одного бренда."
    )
    parser.add_argument("brand", help="Название бренда (например: hikvision, dahua, axis)")
    parser.add_argument("--out", default="db", help="Папка для YAML-файла (по умолчанию: db/)")
    parser.add_argument("--delay", type=float, default=REQUEST_DELAY,
                        help=f"Пауза между запросами в секундах (по умолчанию: {REQUEST_DELAY})")
    args = parser.parse_args()

    brand = args.brand.lower().strip()
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{brand}.yaml"

    print(f"Бренд: {brand}")
    print(f"Папка вывода: {out_dir.resolve()}")
    print(f"Файл: {out_path}")
    print(f"Пауза между запросами: {args.delay} сек")
    print()

    session = requests.Session()
    models = fetch_all_pages(brand, session, args.delay)

    if not models:
        print(f"\n❌ Не удалось получить модели для '{brand}'.")
        print("   Возможные причины: бренд не существует, изменилась структура сайта,")
        print("   либо сайт блокирует запросы.")
        sys.exit(1)

    with open(out_path, "w", encoding="utf-8") as f:
        yaml.dump({brand: models}, f, allow_unicode=True, sort_keys=False, indent=2)

    print(f"\n✅ Сохранено {len(models)} моделей в {out_path}")


if __name__ == "__main__":
    main()
