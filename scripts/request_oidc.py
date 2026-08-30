from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.parse
import urllib.request


def request_token(audience: str) -> str:
    request_url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL")
    request_token = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not request_url or not request_token:
        raise RuntimeError("GitHub OIDC request environment is unavailable")
    separator = "&" if "?" in request_url else "?"
    url = f"{request_url}{separator}{urllib.parse.urlencode({'audience': audience})}"
    request = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {request_token}",
            "Accept": "application/json",
            "User-Agent": "elfeel-release-gateway",
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        payload = json.load(response)
    value = payload.get("value")
    if not isinstance(value, str) or value.count(".") != 2:
        raise RuntimeError("GitHub returned an invalid OIDC token response")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description="Request a GitHub Actions OIDC identity token")
    parser.add_argument("--audience", required=True)
    args = parser.parse_args()
    try:
        value = request_token(args.audience)
    except RuntimeError as error:
        print(error, file=sys.stderr)
        return 1
    print(value)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
