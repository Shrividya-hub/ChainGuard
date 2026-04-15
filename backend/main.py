from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from parser import parse_sbom
from scanner import check_vulnerability
from risk import calculate_risk
from database import collection

app = FastAPI()

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def home():
    return {"message": "ChainGuard API is running"}

@app.post("/analyze")
async def analyze_sbom(file: UploadFile = File(...)):
    try:
        dependencies, format_type = parse_sbom(file.file)
    except Exception:
        return {
            "error": "Unsupported SBOM format or invalid structure"
        }

    results = []

    for dep in dependencies:
        vulns = check_vulnerability(dep["name"], dep["version"])
        risk = calculate_risk(vulns)

        results.append({
            "package": dep["name"],
            "version": dep["version"],
            "risk": risk,
            "vulnerabilities": vulns
        })

    collection.insert_one({
        "format": format_type,
        "results": results
    })

    return {
        "format": format_type,
        "results": results
    }

@app.get("/history")
def get_history():
    data = list(collection.find({}, {"_id": 0}))
    return {"history": data}