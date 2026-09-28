"""
Single source of truth for every pinned value.
No model name, project ID, or URL may appear anywhere else.
"""
import os

# --- Model ---------------------------------------------------------------
# Pinned. Never "-latest": aliases re-point without notice.
MODEL = "gemini-3.8-flash"
MODEL_LOCATION = "global"

# --- Projects ------------------------------------------------------------
RUNTIME_PROJECT = os.getenv("SM_RUNTIME_PROJECT", "sentinelmesh-cp-dev")
TARGET_PROJECT = os.getenv("SM_TARGET_PROJECT", "sentinelmesh-target")

# --- Agent identity ------------------------------------------------------
AGENT_ID = os.getenv("SM_AGENT_ID", "fraud-investigator-01")

# --- Control plane -------------------------------------------------------
# THE one-line swap: "stub" -> "http" on Day 7.
CONTROL_PLANE_MODE = os.getenv("SM_CONTROL_PLANE_MODE", "stub")
CONTROL_PLANE_URL = os.getenv("SM_CONTROL_PLANE_URL", "")
CONTROL_PLANE_TIMEOUT_S = 10
APPROVAL_POLL_INTERVAL_S = 2
APPROVAL_TIMEOUT_S = 120

# --- External-destination simulator ---------------------------------------
EXTERNAL_SINK_URL = os.getenv("SM_EXTERNAL_SINK_URL", "")

# --- Loop safety -----------------------------------------------------------
MAX_DENIALS = 3

# --- ADK wiring ------------------------------------------------------------
# ADK reads these from the environment. Set once here so nothing else
# has to know about them.
os.environ.setdefault("GOOGLE_GENAI_USE_VERTEXAI", "TRUE")
os.environ.setdefault("GOOGLE_CLOUD_PROJECT", RUNTIME_PROJECT)
os.environ.setdefault("GOOGLE_CLOUD_LOCATION", MODEL_LOCATION)
