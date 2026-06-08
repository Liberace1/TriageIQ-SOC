"""Small utility to POST alerts to the dashboard ingest endpoint.

Usage:
  python publisher.py '{"source": "triageiq", "message": "alert"}'

It posts to http://localhost:8000/ingest by default.
"""
import sys
import json
import argparse
import urllib.request

def post_alert(url: str, payload: dict):
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=5) as resp:
        return resp.read().decode()


def main():
    p = argparse.ArgumentParser()
    p.add_argument('json', help='JSON alert or path to file')
    p.add_argument('--url', default='http://localhost:8000/ingest')
    args = p.parse_args()

    try:
        # try parse as JSON string
        payload = json.loads(args.json)
    except Exception:
        # fallback to reading file
        with open(args.json, 'r', encoding='utf-8') as f:
            payload = json.load(f)

    print('posting to', args.url)
    print(post_alert(args.url, payload))


if __name__ == '__main__':
    main()
