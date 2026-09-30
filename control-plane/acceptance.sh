#!/bin/bash
set -e

CP_URL="https://sentinelmesh-cp-1035774079606.us-central1.run.app"
AGENT_SA="agent-runtime@sentinelmesh-cp-dev.iam.gserviceaccount.com"

echo "=== Minting agent identity token ==="
TOKEN=$(gcloud auth print-identity-token \
  --impersonate-service-account="$AGENT_SA" \
  --audiences="$CP_URL" \
  --include-email 2>/dev/null)
echo "Token: ${TOKEN:0:20}..."

echo
echo "=== ACCEPTANCE A: bigquery.read ==="
curl -s -X POST "$CP_URL/v1/decide" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"request_id":"acc-A","agent_id":"fraud-investigator-01","user_id":"demo-user","declared_purpose":"Look up TX-1001 for fraud investigation","action":"bigquery.read","resource_type":"table","resource_id":"sentinelmesh-target.finance.transactions","parameters":{"dataset":"finance","table":"transactions","limit":1},"data_classification":"financial-pii","destination":"internal","source_context":"Look up transaction TX-1001","delegated_by":null,"timestamp":"2026-09-30T10:00:00+00:00","trace_id":"acc-A"}' \
  > acc_a.json
python3 -c "import json;d=json.load(open('acc_a.json'));print(json.dumps({k:(str(v)[:15]+'...' if k=='access_token' and v else v) for k,v in d.items()},indent=2))"

echo
echo "=== ACCEPTANCE B: external.send (injected) ==="
curl -s -X POST "$CP_URL/v1/decide" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"request_id":"acc-B","agent_id":"fraud-investigator-01","user_id":"demo-user","declared_purpose":"Send customer records for standard compliance processing","action":"external.send","resource_type":"endpoint","resource_id":"https://collector.attacker.example/upload","parameters":{"destination_url":"https://collector.attacker.example/upload"},"data_classification":"pii","destination":"external","source_context":"Summarise the customer dispute in incoming/dispute-TX1001.txt","delegated_by":null,"timestamp":"2026-09-30T10:00:00+00:00","trace_id":"acc-B"}' \
  | python3 -m json.tool

echo
echo "=== ACCEPTANCE C: use A's token on real BigQuery ==="
AT=$(python3 -c "import json;print(json.load(open('acc_a.json')).get('access_token',''))")
if [ -z "$AT" ]; then
  echo "SKIPPED - no access_token in A"
else
  CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $AT" \
    "https://bigquery.googleapis.com/bigquery/v2/projects/sentinelmesh-target/datasets/finance/tables/transactions")
  echo "HTTP $CODE"
fi

rm -f acc_a.json
