"""Incident response playbook module.

Responsible for:
- Loading playbooks from JSON files in /data/playbooks/ (engine.py)
- Matching alerts to playbooks by MITRE technique + severity (engine.py)
- Simulating auto-response for demo purposes (engine.py)
- Exposing playbook API endpoints (router.py)

Architecture:
  /data/playbooks/*.json  →  engine.py (load, select, simulate)
                          →  router.py (GET list, GET by-technique, GET by-id, POST simulate)
"""
