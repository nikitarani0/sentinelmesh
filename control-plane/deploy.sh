#!/bin/bash
set -e
gcloud run deploy sentinelmesh-cp \
  --source=. \
  --project=sentinelmesh-cp-dev \
  --region=us-central1 \
  --no-allow-unauthenticated \
  --service-account=sentinelmesh-cp@sentinelmesh-cp-dev.iam.gserviceaccount.com \
  --env-vars-file=env.yaml
