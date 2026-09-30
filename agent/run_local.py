"""
Run the agent locally against real data in sentinelmesh-target.

    python run_local.py "Look up transaction TX-1001 and summarise it"

Stub mode uses YOUR login (ADC). On Cloud Run, the agent-runtime identity
has no access to target data by design.
"""
import asyncio
import logging
import sys

from google.adk.runners import InMemoryRunner
from google.genai import types

from enterprise_agent.agent import root_agent

APP, USER = "sentinelmesh", "nik"


async def main(prompt: str) -> None:
    runner = InMemoryRunner(agent=root_agent, app_name=APP)
    session = await runner.session_service.create_session(app_name=APP, user_id=USER)
    msg = types.Content(role="user", parts=[types.Part(text=prompt)])

    async for event in runner.run_async(user_id=USER, session_id=session.id,
                                        new_message=msg):
        for part in (event.content.parts if event.content else None) or []:
            if part.function_call:
                args = dict(part.function_call.args or {})
                print(f"\n  -> {part.function_call.name}({args})")
            if part.function_response:
                r = part.function_response.response or {}
                print(f"  <- {part.function_response.name}: "
                      f"executed={r.get('executed')} decision={r.get('decision')}")
            if part.text:
                print(f"\n{part.text}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING,
                        format="%(levelname)s %(name)s: %(message)s")
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    asyncio.run(main(" ".join(sys.argv[1:])))
