# Phantom Network Scanner

Phantom Network Scanner is a full-stack network reconnaissance and reporting tool built to identify exposed TCP ports, estimate security risk, and generate human-readable threat intelligence reports. It combines a FastAPI backend, an Nmap-based scanner, a SQLite database, and a React frontend to present scan results in a structured security dashboard.

## Purpose

The project is designed to help security teams, administrators, and learners quickly answer three questions:

- Which ports are open on a target host?
- How risky does the exposed surface appear?
- What actions should be taken next?

Instead of only returning raw scan output, Phantom Network Scanner adds risk scoring, historical scan tracking, anomaly detection, and optional Gemini-powered analysis so the results are easier to interpret and act on.

## How It Works

### 1. User starts a scan

From the frontend, the user enters a target IPv4 address and chooses a scan mode:

- TCP Connect scan (`-sT`)
- SYN scan (`-sS`)
- Service version scan (`-sV`)

The UI then sends the request to the backend API.

### 2. Backend validates and scans the target

The FastAPI service validates the IP address, initializes Nmap, and scans ports `1-600` on the target host. For each detected port, it collects:

- port number
- status
- service name
- product and version details when available
- an assigned risk label

### 3. Risk scoring is calculated

The backend applies a rule-based scoring model:

- open ports add base risk
- sensitive services such as RDP, SSH, FTP, Telnet, SMB, and database ports increase the score further
- the final score is capped at 100

The score is then mapped to a risk level:

- Low
- Medium
- High

### 4. Scan history is stored locally

Every scan and its detected ports are saved in a local SQLite database (`phantom.db`). This enables:

- scan history review
- risk trend visibility
- CSV export of past scans
- training data for anomaly detection

### 5. Machine learning checks for anomalies

If enough historical scans exist, the backend trains a One-Class SVM model on past risk scores and open-port counts. The current scan is compared against historical behavior to flag unusual patterns that may deserve closer review.

### 6. Optional AI report generation

The Reports tab can generate a concise threat analysis using Google Gemini. The backend sends a structured prompt containing the scan summary and asks the model to return:

- a short threat analysis
- a mitigation strategy

The API key is stored locally in the browser and is not written to the database.

## Project Structure

- `server/` contains the FastAPI application, database models, and scanner logic.
- `client/` contains the React dashboard used to launch scans and view results.
- `phantom.db` is created automatically in the server directory when the backend runs.

## Key Features

- Target IP validation before scanning
- Nmap-based TCP port scanning
- Service and version discovery
- Rule-based port risk scoring
- Historical scan persistence in SQLite
- CSV export of scan history
- Optional Gemini AI report generation
- SVM-based anomaly detection from historical scans
- Dashboard views for scanner, history, reports, and settings

## Tech Stack

### Backend

- FastAPI
- SQLAlchemy
- SQLite
- python-nmap
- scikit-learn
- Google Generative AI

### Frontend

- React
- Vite
- Axios
- Tailwind CSS

## Setup

### Prerequisites

- Python 3.10 or newer
- Node.js 18 or newer
- Nmap installed and available in your system PATH

### Backend

```bash
cd server
pip install -r requirements.txt
uvicorn main:app --reload
```

The backend runs on `http://127.0.0.1:8000` by default.

### Frontend

```bash
cd client
npm install
npm run dev
```

The frontend runs on `http://localhost:5173` by default.

## Environment Variables

### Backend

- `API_PORT` - optional port for the FastAPI server
- `GEMINI_API_KEY` - optional API key for AI report generation

### Frontend

- `VITE_API_URL` - backend base URL, defaults to `http://localhost:8000`

## Typical Workflow

1. Start the backend and frontend.
2. Enter a target IPv4 address in the Scanner tab.
3. Choose a scan type and run the scan.
4. Review open ports, risk level, and anomaly alerts.
5. Check the History tab for previous scans.
6. Use Reports to generate an AI-written summary.
7. Use Settings to save a Gemini API key, export CSV data, or clear scan history.

## Notes

- The scanner currently focuses on IPv4 targets.
- Nmap must be installed locally for scans to work.
- AI report generation is optional and only works when a valid Gemini API key is available.
- Scan data is stored locally, making the project suitable for demos, labs, and internal security checks.

## License

No license file is included in this repository. Add one if you plan to distribute or reuse the project publicly.
