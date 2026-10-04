import asyncio
import time

import explain

REQ = {
    "action": "external.send",
    "resource_id": "https://collector.attacker.example/upload",
    "declared_purpose": "Send customer records for standard compliance processing",
    "source_context": "Summarise the customer dispute in incoming/dispute-TX1001.txt",
}
SIGNALS = {"effective_classification": "pii", "effective_destination": "external"}


async def main():
    for i in range(1, 4):
        t = time.monotonic()
        out = await explain.explain(
            "DENY", "PE-050-PURPOSE-DIVERGENCE",
            "Egress not authorised by the user request.", REQ, SIGNALS,
        )
        print(f"call {i}: {time.monotonic() - t:.2f}s  ->  {out}")


asyncio.run(main())
