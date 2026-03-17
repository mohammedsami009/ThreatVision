# ThreatVision + Vibex

> AI-driven integrated intrusion detection and digital twin security dashboard for IoT fleet monitoring.

## Overview

ThreatVision + Vibex is a combined cybersecurity project with two complementary apps:

- **ThreatVision** (Streamlit): digital twin dashboard for fleet device behavior, anomaly detection and trust scoring.
- **Vibex** (Dash): network IDS using Isolation Forest, Autoencoder, LSTM and live packet capture.

This repository supports:
- real-time packet capture from NIC via Scapy,
- dynamic anomaly scoring,
- historical trend + alert dashboard,
- integration mode where Vibex is embedded into ThreatVision.

---

## Repository Structure

```
ThreatVision/
  ThreatVision/
    app.py
    auth.py
    auth_page.py
    dashboard.py
    hardware_dashboard.py
    hardware_registry.py
    model.py
    engine.py
    registry.py
    sniffer.py
    ui.py
    check_setup.py
    setup_data.py
    train.py
    test_interfaces.py
    test_model_logic.py
    test_sniff.py
    threatvision_autoencoder.pth
    requirements.txt
    README.md
    PROJECT_ARCHITECTURE.md
  vibex/
    main.py
    dashboard.py
    capture/
      __init__.py
      sniffer.py
      feature_extractor.py
    models/
      __init__.py
      autoencoder.py
      isolation_forest.py
      lstm.py
    utils/
      __init__.py
      data_generator.py
      predictor.py
    requirements.txt
  data/
    cicids_benign.csv
    cicids_ddos.csv
    cicids_portscan.csv
  reports/
  PROGRESS.md
  pyrightconfig.json
```

---

## Key Features

- **Streamlit fleet dashboard**
  - device list + map
  - device digital twin control sliders
  - trust score (0-100), health status
  - threat + remediation logs
- **Live hardware integration**
  - Scapy sniffer for NIC packet frames
  - feature extraction per MAC
- **ML engine**
  - LSTM autoencoder reconstruction error
  - Jensen-Shannon divergence
  - trust score penalties
- **Vibex IDS**
  - live dashboard (Dash) with timeline, pie, and malicious table
  - ensemble packet classification (IF, AE, LSTM)
- **Integrated mode**
  - ThreatVision (8501) + Vibex (8050)
  - iframe-based embed with local service thread

---

## Prerequisites

- OS: Windows 10/11, Linux, macOS
- Python 3.10+ (3.13 recommended)
- Admin/root required for raw packet capture (Scapy)
- `git` (optional)

---

## Installation

### ThreatVision

```powershell
cd d:\userfiles\Desktop\ThreatVision\ThreatVision
python -m venv .\venv
.\venv\Scripts\Activate.ps1  # Linux/macOS: source ./venv/bin/activate
pip install -r requirements.txt
pip install dash plotly
```

### Vibex

```powershell
cd d:\userfiles\Desktop\ThreatVision\vibex
python -m venv .\venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

---

## Running

### Start ThreatVision

```powershell
cd d:\userfiles\Desktop\ThreatVision\ThreatVision
.\venv\Scripts\Activate.ps1
streamlit run app.py
```

Open: `http://localhost:8501`

### Start Vibex standalone

```powershell
cd d:\userfiles\Desktop\ThreatVision\vibex
.\venv\Scripts\Activate.ps1
python main.py
```

Open: `http://localhost:8050`

---

## First-run checks

```powershell
python check_setup.py
python model.py
python engine.py
pip install pytest
pytest -q
```

---

## Auth

- `auth.py` uses SQLite at `threatvision_auth.db` (or `THREATVISION_AUTH_DB_PATH`)
- Auto-create admin if `THREATVISION_ADMIN_EMAIL` and `THREATVISION_ADMIN_PASSWORD` provided

---

## Config options

- `ENABLE_PACKET_SNIFF` (new) to toggle sniffing
- `THREATVISION_ADMIN_EMAIL`
- `THREATVISION_ADMIN_PASSWORD`
- `THREATVISION_AUTH_DB_PATH`

---

## Vibex telemetry features

From `vibex/capture/feature_extractor.py`, each packet yields 8 features:
1. `pkt_size`
2. `is_arp`
3. `is_broadcast_dst`
4. `is_broadcast_src`
5. `psrc_last` (ARP source IP last octet)
6. `pdst_last` (ARP dst IP last octet)
7. `hwsrc_first` (ARP src MAC first byte)
8. `inter_arrival` (seconds since previous packet)

---

## Anomaly scoring flow

1. packet → features
2. models: Isolation Forest, Autoencoder, LSTM
3. ensemble voting + verdict
4. Dashboard update

---

## Testing

- `ThreatVision/ThreatVision/test_interfaces.py`
- `ThreatVision/ThreatVision/test_model_logic.py`
- `ThreatVision/ThreatVision/test_sniff.py`

Run: `pytest -q`

---

## Roadmap (optional enhancements)

- multiclass attack classifier (DDoS/BruteForce/PortScan)
- persistence in DB (Postgres/Mongo)
- alert export (SIEM/Kafka)
- RBAC and auth hardening
- containerization (`Dockerfile`, `docker-compose`)
- websocket/low-latency dashboard

---

## Short summary

1. Launch ThreatVision (8501)
2. Launch Vibex (8050)
3. Monitor live model decisions and trust scores
4. Optional: ping `http://localhost:8050` from iframe integration in ThreatVision

---

## Notes

- This project emphasizes broad anomaly and trust scoring, not yet detailed attack taxonomy.
- ICMP is detected but not restricted; the approach is general traffic analysis for broader threat coverage.
