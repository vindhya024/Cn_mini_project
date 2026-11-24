# Network Intrusion Detection and Response System (`Cn_mini_project`)

A Python-based Computer Networks mini-project simulating a network topology, generating traffic, detecting suspicious or anomalous network activity, and executing automated response actions alongside client-server communication.

## Repository Structure

* [`topo.py`] Defines and initializes the network topology.
* [`traffic.py`] Generates normal and/or anomalous traffic across the topology.
* [`detector.py`] Monitors traffic/events and flags intrusion or anomaly conditions.
* [`response.py`] Handles mitigation/response actions and logging when an intrusion is detected.
* [`client.py`] Client-side script for network communication/testing.
* [`server.py`] Server-side script for network communication/testing.
* [`project_report_cn.pdf`] Detailed project report, architecture notes, and experimental results.

## Prerequisites
OS / Environment: Linux / Mininet (or Python environment matching your topology setup)
Python: Python 3.x
Dependencies: Standard library modules (such as `socket`, `csv`, etc.) and any external packages used in your scripts (for example, Mininet if using `topo.py` with Mininet).

```bash
