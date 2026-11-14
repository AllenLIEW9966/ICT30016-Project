"""Asynchronous lookup of advisories for exact public registry coordinates."""
import asyncio
import re
import time
from urllib.parse import quote

import httpx

BASE = "https://api.osv.dev/v1/"
CACHE = {}
TTL = 6 * 3600


async def lookup(keys, transport=None, cache=None):
    cache = CACHE if cache is None else cache
    now = time.monotonic()
    keys = list(dict.fromkeys(keys))
    result = {k: cache[k][1] for k in keys if k in cache and cache[k][0] > now}
    pending = [k for k in keys if k not in result]
    if not pending:
        return result
    try:
        async with asyncio.timeout(25), httpx.AsyncClient(
            base_url=BASE, timeout=6, transport=transport
        ) as client:
            details = {}
            async def fetch_detail(vid):
                if vid.startswith("CVE-"):
                    details[vid] = [vid]
                    return
                try:
                    detail = await client.get("vulns/" + quote(vid, safe=""))
                    aliases = detail.raise_for_status().json().get("aliases", [])
                    details[vid] = [x for x in aliases if re.fullmatch(r"CVE-\d{4}-\d+", x)] or [vid]
                except httpx.HTTPError:
                    details[vid] = [vid]
            for start in range(0, len(pending), 1000):
                active = [(key, None) for key in pending[start:start + 1000]]
                found = {key: set() for key, _ in active}
                while active:
                    queries = []
                    for (eco, name, version), token in active:
                        query = {"package": {"ecosystem": eco, "name": name}, "version": version}
                        if token:
                            query["page_token"] = token
                        queries.append(query)
                    response = await client.post("querybatch", json={"queries": queries})
                    rows = response.raise_for_status().json()["results"]
                    missing = list(dict.fromkeys(v["id"] for row in rows for v in row.get("vulns", [])
                                                 if v["id"] not in details))
                    for offset in range(0, len(missing), 8):
                        await asyncio.gather(*(fetch_detail(v) for v in missing[offset:offset + 8]))
                    next_page = []
                    for (key, _), row in zip(active, rows, strict=True):
                        for vuln in row.get("vulns", []):
                            vid = vuln["id"]
                            found[key].update(details[vid])
                        if row.get("next_page_token"):
                            next_page.append((key, row["next_page_token"]))
                        else:
                            result[key] = sorted(found[key])
                            if len(cache) >= 20000 and key not in cache:
                                cache.pop(next(iter(cache)))
                            cache[key] = (time.monotonic() + TTL, result[key])
                    active = next_page
    except (httpx.HTTPError, TimeoutError, KeyError, ValueError, TypeError, AttributeError):
        pass
    return result
