from fastapi import FastAPI, UploadFile, File, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
import shutil
import os
import uuid
from vol_runner import VolatilityRunner

app = FastAPI(title="Masala Memory Engine")

UPLOAD_DIR = "./uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

templates = Jinja2Templates(directory="templates")

# In-memory storage for analysis sessions
ANALYSIS_SESSIONS = {}

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse(
        request=request, 
        name="index.html", 
        context={}
    )

@app.post("/analyze")
async def analyze_memory(request: Request, file: UploadFile = File(...)):
    session_id = str(uuid.uuid4())[:8]
    file_path = os.path.join(UPLOAD_DIR, f"{session_id}_{file.filename}")
    
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
        
    runner = VolatilityRunner(file_path)
    
    pslist_raw = runner.run_plugin("pslist.PsList")
    netscan_raw = runner.run_plugin("netscan.NetScan")
    malfind_raw = runner.run_plugin("malfind.Malfind")

    # Simple line-count heuristics for dynamic metrics
    process_count = len([line for line in pslist_raw.splitlines() if line.strip() and not line.startswith("Progress")])
    net_count = len([line for line in netscan_raw.splitlines() if line.strip() and not line.startswith("Progress")])
    threat_count = 1 if "PAGE_EXECUTE_READWRITE" in malfind_raw else 0

    ANALYSIS_SESSIONS[session_id] = {
        "filename": file.filename,
        "session_id": session_id,
        "pslist": pslist_raw,
        "netscan": netscan_raw,
        "malfind": malfind_raw,
        "metrics": {
            "processes": max(0, process_count - 2),
            "sockets": max(0, net_count - 2),
            "threats": threat_count
        }
    }

    return RedirectResponse(url=f"/dashboard/{session_id}", status_code=303)

@app.get("/dashboard/{session_id}", response_class=HTMLResponse)
async def view_dashboard(request: Request, session_id: str):
    session_data = ANALYSIS_SESSIONS.get(session_id)
    if not session_data:
        return RedirectResponse(url="/")
        
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={"data": session_data}
    )