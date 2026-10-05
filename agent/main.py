"""
HTTP entrypoint for Cloud Run.

Stateless: one ADK session per request, deleted afterwards. Responses carry
the agent's answer plus a decision trace per tool call — never the raw data a
tool returned. Rows stay inside the agent; only the agent's own answer leaves.
"""
from __future__ import annotations

import logging
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from google.adk.runners import InMemoryRunner
from google.genai import types
from pydantic import BaseModel, Field

import attacks
import config
from enterprise_agent.agent import root_agent

logging.basicConfig(level=logging.INFO,
                    format="%(levelname)s %(name)s: %(message)s")
log = logging.getLogger("sentinelmesh.http")

APP = "sentinelmesh"
# This endpoint is public and unauthenticated, so anything a caller sends is
# a claim. The user identity is fixed server-side: a caller must never be
# able to tell the control plane it is someone else.
DEMO_USER = "demo-user"

app = FastAPI(title="SentinelMesh Enterprise Agent")
_runner = InMemoryRunner(agent=root_agent, app_name=APP)
_PLAYGROUND = (Path(__file__).parent / "playground.html").read_text(encoding="utf-8")


class RunRequest(BaseModel):
    prompt: str = Field(min_length=1, max_length=2000)


class AttackRequest(BaseModel):
    scenario: str = Field(min_length=1, max_length=64)


async def _drive(runner: InMemoryRunner, prompt: str) -> dict:
    """Run one prompt through an ADK runner and return answer + decision trace."""
    session = await runner.session_service.create_session(app_name=APP, user_id=DEMO_USER)
    trace_id = None
    calls: dict[str, dict] = {}
    order: list[str] = []
    answer: list[str] = []

    try:
        msg = types.Content(role="user", parts=[types.Part(text=prompt)])
        async for event in runner.run_async(
                user_id=DEMO_USER, session_id=session.id, new_message=msg):
            # Same id the executor sends to the control plane as trace_id,
            # so this response lines up with the control plane's audit log.
            trace_id = trace_id or getattr(event, "invocation_id", None)
            for part in (event.content.parts if event.content else None) or []:
                if part.function_call:
                    key = part.function_call.id or str(len(order))
                    order.append(key)
                    calls[key] = {"tool": part.function_call.name,
                                  "args": dict(part.function_call.args or {})}
                elif part.function_response:
                    key = part.function_response.id or (order[-1] if order else "?")
                    r = part.function_response.response or {}
                    calls.setdefault(key, {"tool": part.function_response.name})
                    calls[key].update({
                        "decision": r.get("decision"),
                        "executed": r.get("executed"),
                        "risk_score": r.get("risk_score"),
                        "reason": r.get("reason"),
                        "error": r.get("error"),
                    })
                elif part.text and event.author != "user":
                    answer.append(part.text)
    finally:
        await runner.session_service.delete_session(
            app_name=APP, user_id=DEMO_USER, session_id=session.id)

    return {"trace_id": trace_id,
            "control_plane_mode": config.CONTROL_PLANE_MODE,
            "user_prompt": prompt,
            "answer": "".join(answer).strip(),
            "tool_calls": [calls[k] for k in order if k in calls]}


async def run_attack(scenario_id: str) -> dict:
    """Raises KeyError for an unknown scenario."""
    sc = attacks.SCENARIOS[scenario_id]
    runner = InMemoryRunner(agent=attacks.compromised_agent(scenario_id), app_name=APP)
    result = await _drive(runner, sc["user_prompt"])
    return {"scenario": scenario_id, "title": sc["title"], **result}


@app.get("/", response_class=HTMLResponse)
def playground() -> str:
    return _PLAYGROUND


# Not "/healthz": Cloud Run reserves paths ending in "z" on *.run.app,
# so that route never reaches the container.
@app.get("/health")
def health() -> dict:
    return {"ok": True, "agent_id": config.AGENT_ID, "model": config.MODEL,
            "control_plane_mode": config.CONTROL_PLANE_MODE}


@app.get("/api/scenarios")
def scenarios() -> list[dict]:
    return [{"id": k, "title": v["title"], "summary": v["summary"],
             "user_prompt": v["user_prompt"]}
            for k, v in attacks.SCENARIOS.items()]


@app.post("/v1/run")
async def run(req: RunRequest) -> dict:
    try:
        return await _drive(_runner, req.prompt)
    except Exception:
        log.exception("agent run failed")
        raise HTTPException(status_code=502, detail="agent run failed")


@app.post("/v1/attack")
async def attack(req: AttackRequest) -> dict:
    if req.scenario not in attacks.SCENARIOS:
        raise HTTPException(status_code=404, detail="unknown scenario")
    try:
        return await run_attack(req.scenario)
    except Exception:
        log.exception("attack run failed")
        raise HTTPException(status_code=502, detail="attack run failed")
