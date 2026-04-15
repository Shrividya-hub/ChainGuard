# 🔐 ChainGuard: Supply Chain Malware Detection using SBOM Analysis

## 🚀 Overview

ChainGuard is a cybersecurity tool that analyzes Software Bill of Materials (SBOM) and dependency files to detect vulnerable or risky components in software projects.

Modern applications rely heavily on third-party libraries, increasing exposure to supply chain attacks. ChainGuard helps identify these risks by scanning dependencies and checking them against known vulnerability databases.

---

## 🎯 Features

* 🔍 Multi-format support:

  * SBOM JSON (CycloneDX, SPDX)
  * XML SBOM
  * SPDX text format
  * package.json (Node.js)

* 🛡️ Vulnerability detection using OSV database

* ⚠️ Risk classification:

  * 🔴 HIGH → Multiple vulnerabilities
  * 🟡 MEDIUM → One vulnerability
  * 🟢 LOW → No vulnerabilities

* 📊 Dashboard:

  * Dependency analysis
  * Risk summary
  * Visual distribution

* 🗂️ Scan history using MongoDB

---

## 🏗️ Tech Stack

* React.js
* FastAPI (Python)
* MongoDB
* OSV (Open Source Vulnerabilities Database)

---

## ⚙️ Installation & Setup

```bash
git clone https://github.com/YOUR-USERNAME/chainguard.git
cd chainguard

python -m venv venv
venv\Scripts\activate   # Windows
pip install -r requirements.txt
uvicorn main:app --reload

npm install
npm start
```

(Optional) Run MongoDB:

```bash
mongod
```

---

## 🧪 Usage

1. Open the application in browser
2. Upload a file (SBOM or package.json)
3. Click **Analyze**
4. View:

   * Detected format
   * Risk levels
   * Vulnerabilities
   * Summary dashboard

---

## 📂 Supported Input Formats

* SBOM JSON
* XML SBOM
* SPDX Text
* package.json

---

## 📊 Risk Classification Logic

* LOW → No vulnerabilities found
* MEDIUM → One vulnerability detected
* HIGH → Two or more vulnerabilities detected

---

## 🧠 How It Works

1. File Upload
2. SBOM / Dependency Parsing
3. Component Extraction
4. OSV API Query
5. Risk Classification
6. Results Display

---

## 🖼️ Workflow

Input File (SBOM / package.json)
↓
Parser (JSON/XML/SPDX)
↓
Dependency Extraction
↓
OSV Vulnerability Check
↓
Risk Classification
↓
Frontend Dashboard

---

## 🚀 Future Enhancements

* Machine learning-based risk prediction
* CI/CD integration
* Real-time monitoring
* Advanced visualization

---

## 📌 Note

This project is developed for educational purposes to demonstrate supply chain security using SBOM analysis.
