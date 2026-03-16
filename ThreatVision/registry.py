"""registry.py — IoT device registry and session-state defaults."""

import os
import random
import pandas as pd

# Default to New York City if not specified
CENTER_LAT = float(os.getenv("MAP_CENTER_LAT", 40.7128))
CENTER_LON = float(os.getenv("MAP_CENTER_LON", -74.0060))

from data_provider import ALIEN_BASELINES

def _rand_offset():
    return random.uniform(-0.02, 0.02)

IOT_REGISTRY = {
    "DEV-001": {"name": "TV-PUMP-01",        "type": "Pump",              "sector": "1",   "baseline": ALIEN_BASELINES, "icon": "🚰", "lat": CENTER_LAT + _rand_offset(), "lon": CENTER_LON + _rand_offset()},
    "DEV-002": {"name": "Assembly Arm",      "type": "Robotic Arm",       "sector": "2",   "baseline": ALIEN_BASELINES, "icon": "🦾", "lat": CENTER_LAT + _rand_offset(), "lon": CENTER_LON + _rand_offset()},
    "DEV-003": {"name": "Grid Node 0X",      "type": "Smart Grid Node",   "sector": "3",   "baseline": ALIEN_BASELINES, "icon": "⚡", "lat": CENTER_LAT + _rand_offset(), "lon": CENTER_LON + _rand_offset()},
    "DEV-004": {"name": "Cryo-Storage A",    "type": "Bio-Storage Fridge","sector": "4",   "baseline": ALIEN_BASELINES, "icon": "❄️", "lat": CENTER_LAT + _rand_offset(), "lon": CENTER_LON + _rand_offset()},
    "DEV-005": {"name": "Mixer V-12",        "type": "Chemical Mixer",    "sector": "5",   "baseline": ALIEN_BASELINES, "icon": "🧪", "lat": CENTER_LAT + _rand_offset(), "lon": CENTER_LON + _rand_offset()},
    "DEV-006": {"name": "Security Cam 1",    "type": "Camera",            "sector": "6",   "baseline": ALIEN_BASELINES, "icon": "📷", "lat": CENTER_LAT + _rand_offset(), "lon": CENTER_LON + _rand_offset()},
    "DEV-007": {"name": "Security Cam 2",    "type": "Camera",            "sector": "7",   "baseline": ALIEN_BASELINES, "icon": "📷", "lat": CENTER_LAT + _rand_offset(), "lon": CENTER_LON + _rand_offset()},
    "DEV-008": {"name": "Coolant Pump",      "type": "Pump",              "sector": "8",   "baseline": ALIEN_BASELINES, "icon": "⚙️", "lat": CENTER_LAT + _rand_offset(), "lon": CENTER_LON + _rand_offset()},
    "DEV-009": {"name": "Welding Arm",       "type": "Robotic Arm",       "sector": "9",   "baseline": ALIEN_BASELINES, "icon": "🤖", "lat": CENTER_LAT + _rand_offset(), "lon": CENTER_LON + _rand_offset()},
    "DEV-010": {"name": "Main Grid Relay",   "type": "Smart Grid Node",   "sector": "7-G", "baseline": ALIEN_BASELINES, "icon": "🔌", "lat": CENTER_LAT + _rand_offset(), "lon": CENTER_LON + _rand_offset()},
}

SESSION_DEFAULTS = {
    "page":                          "fleet",
    "active_device":                 None,
    "device_health":                 {k: "Healthy" for k in IOT_REGISTRY},
    "packet_history":                {}, # dev_id -> df
    "threat_log":                    {}, # dev_id -> list
    "remediation_log":               {}, # dev_id -> list
    "trust_scores":                  {}, # dev_id -> float
    "audit_logs":                    [],
    "remediation_locked":            False,
    "attack_step":                   {},
    "math_mode_active":              False,
    "jsd_history":                   {}, # dev_id -> list
    "pulse_mse_history":             {}, # dev_id -> list
    "pulse_jsd_history":             {}, # dev_id -> list
    "reconstruction_errors_history": {}, # dev_id -> list of lists
    # auth
    "authenticated":                 False,
    "user_email":                    None,
    "login_error":                   None,
    "password_visible":              False,
    "register_mode":                 False,
    "last_alert_sent":               {},
    # hardware / sniffer
    "sniffer_active":                False,
    "hw_active_device":              None,
    "hw_calibrating":                False,
}