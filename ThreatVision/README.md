# ThreatVision + Vibex Integrated Deployment

## Overview

This repository contains two projects:

- **ThreatVision**: Streamlit-based AI-driven digital twin security dashboard.
- **Vibex**: Dash-based network IDS with isolation forest, autoencoder, LSTM, and live packet capture.

The `ThreatVision` app now includes a dedicated sidebar route (`Vibex IDS`) that loads a Vibex dashboard in an iframe via local port `8050`, run in a background thread.

---

## 1) Prerequisites

- Windows 10/11, Linux, or macOS
- Python 3.10+ (3.13 is used in this project)
- `git` (optional)

---

## 2) Repo structure

```
ThreatVision/
  ThreatVision/          # main app
    app.py
    auth.py
    auth_page.py
    dashboard.py
    hardware_dashboard.py
    model.py
    registry.py
    sniffer.py
    ...
    requirements.txt
    README.md
  vibex/                 # vibex app
    main.py
    dashboard.py
    capture/
    models/
    utils/
```

---

## 3) Setup

### 3.1 Create virtual environment (ThreatVision)

```powershell
cd d:\userfiles\Desktop\ThreatVision\ThreatVision
python -m venv .\venv
.\venv\Scripts\Activate.ps1
```

### 3.2 Install Python dependencies (ThreatVision)

```powershell
pip install -r requirements.txt
```

### 3.3 Install Vibex dependencies

```powershell
cd d:\userfiles\Desktop\ThreatVision\vibex
pip install dash plotly
```

If `requirements.txt` in `vibex` has additional packages, install them too.

---

## 4) Run first-time check

```powershell
cd d:\userfiles\Desktop\ThreatVision\ThreatVision
.\venv\Scripts\Activate.ps1
python check_setup.py
python model.py
python engine.py
```

- `check_setup.py`: verifies dependencies.
- `model.py`: tests autoencoder architecture and basic inference.
- `engine.py`: tests trust score pipeline.

---

## 5) Run ThreatVision + integrated Vibex

```powershell
cd d:\userfiles\Desktop\ThreatVision\ThreatVision
.\venv\Scripts\Activate.ps1
streamlit run app.py
```

1. Open URL shown by Streamlit (usually `http://localhost:8501`).
2. Log in through the built-in auth page.
3. In the sidebar, choose:
   - `ThreatVision` → main fleet/hardware pages
   - `Vibex IDS` → integrated Vibex page (iframe)

---

## 6) Run Vibex standalone (optional)

```powershell
cd d:\userfiles\Desktop\ThreatVision\vibex
python main.py
```

Then browse to `http://localhost:8050`.

---

## 7) Notes on integration

- ThreatVision route is preserved and unaffected.
- `Vibex IDS` route starts a daemon thread that launches Vibex Dash on port `8050`, then embeds an iframe.
- If the iframe fails (CSP or browser policy), use the standalone command above.

---

## 8) Troubleshooting

- `ModuleNotFoundError`:
  - ensure venv is activated
  - install missing package

- `Port already in use` for 8050:
  - stop conflicting process
  - change port in `app.py` and `vibex/dashboard.py`

- `Streamlit old cache`:
  - `streamlit cache clear`

---

## 9) Tests

Run unit tests:

```powershell
cd d:\userfiles\Desktop\ThreatVision\ThreatVision
.\venv\Scripts\Activate.ps1
pip install pytest
pytest -q
```

---

## 10) Quick command summary

```powershell
cd d:\userfiles\Desktop\ThreatVision\ThreatVision
python -m venv .\venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install dash plotly
streamlit run app.py
```

---

## 11) Environment variables (optional admin auto-provision)

Set:

- `THREATVISION_ADMIN_EMAIL`
- `THREATVISION_ADMIN_PASSWORD`

Then run `app.py`; initial admin user creation is automatic.
