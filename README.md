# Masala Memory Engine

Masala Memory Engine is an automated web dashboard built with FastAPI, Jinja2, and Volatility 3 for rapid volatile memory (RAM) forensic triage and analysis.

## Overview

The platform automates the extraction and presentation of critical operating system artifacts from volatile RAM dumps (.raw, .vmem, .dd). It simplifies digital forensic triage through a multi-page workspace and structured analytics dashboard.

## Key Features

- **Automated Volatility 3 Pipeline**: Runs `pslist`, `netscan`, and `malfind` plugins concurrently.
- **Session Architecture**: Handles dynamic analysis runs with UUID-based tracking (`/dashboard/{session_id}`).
- **Threat Detection**: Automatically flags suspicious memory regions, such as RWX permissions (`PAGE_EXECUTE_READWRITE`) and unbacked PE headers (`MZ` artifacts).
- **Interactive UI**: Includes live output filtering, dynamic metric counters, and tabbed terminal views.

## Project Structure

```text
.
├── main.py
├── vol_runner.py
├── templates/
│   ├── index.html
│   └── dashboard.html
├── uploads/
├── requirements.txt
└── README.md
