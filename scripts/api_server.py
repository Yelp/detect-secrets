from fastapi import FastAPI, Request
from typing import List
from detect_secrets.core.scan import scan_line

app = FastAPI()

@app.post("/scan_logs/")
async def scan_logs(request: Request):
    data = await request.json()
    logs: List[str] = data.get("logs", [])
    
    results = []
    for lineno, line in enumerate(logs, start=1):
        for secret in scan_line(line):
            results.append({
                'line_number': lineno,
                'type': secret.type,
                'hashed_secret': secret.secret_hash,
                # optionally add 'secret_value': secret.secret_value if safe
            })
    return {"matches": results}
