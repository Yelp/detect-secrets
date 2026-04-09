from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, HTMLResponse
from typing import List
import json
from datetime import datetime
from pathlib import Path
from detect_secrets.core.scan import scan_line
from detect_secrets.settings import transient_settings
from detect_secrets.core.plugins.util import get_mapping_from_secret_type_to_class

app = FastAPI()

def get_scan_settings():
    """Configure scan settings with all available detectors"""
    mapping = get_mapping_from_secret_type_to_class()
    return {
        'plugins_used': [
            {'name': cls.__name__}
            for cls in mapping.values()
        ]
    }

@app.get("/")
async def root():
    """Root endpoint that shows API usage instructions"""
    return HTMLResponse("""
        <html>
            <body>
                <h1>Detect-Secrets API</h1>
                <h2>Available Endpoints:</h2>
                <ul>
                    <li><b>POST /run_original_scan/</b> - Scan logs for secrets</li>
                </ul>
                <h2>Example Usage:</h2>
                <pre>
POST /run_original_scan/
Content-Type: application/json

{
    "logs": [
        "line 1 to scan",
        "line 2 to scan",
        "..."
    ]
}
                </pre>
            </body>
        </html>
    """)

@app.post("/run_original_scan/")
async def scan_logs(request: Request):
    data = await request.json()
    logs: List[str] = data.get("logs", [])
    
    results = []
    # Use transient_settings to ensure all detectors are properly configured
    with transient_settings(get_scan_settings()):
        for lineno, line in enumerate(logs, start=1):
            for secret in scan_line(line):
                results.append({
                    'line_number': lineno,
                    'type': secret.type,
                    'hashed_secret': secret.secret_hash,
                    'secret_value': secret.secret_value,  # Adding this for debugging
                })
    
    # Create output filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = Path(f"scan_results_{timestamp}.json")
    
    # Write the results to the JSON file
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump({
            "matches": results,
            "scan_time": timestamp,
            "total_lines_scanned": len(logs)
        }, f, indent=2)
    
    # Return both the results and the file information
    return JSONResponse({
        "matches": results,
        "output_file": str(output_file),
        "scan_time": timestamp,
        "total_lines_scanned": len(logs)
    })
