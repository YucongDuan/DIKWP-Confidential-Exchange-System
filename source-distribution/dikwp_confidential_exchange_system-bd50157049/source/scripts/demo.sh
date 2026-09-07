#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python -m pip install -e . >/dev/null
rm -rf artifacts/demo identities
mkdir -p artifacts/demo identities
python -m dikwp_confidential_exchange.cli init --name Alice --out identities/alice --passphrase alice-pass
python -m dikwp_confidential_exchange.cli init --name Bob --out identities/bob --passphrase bob-pass
python -m dikwp_confidential_exchange.cli compile --in examples/zdc_message.yaml --codebook codebooks/dikwp_secure_exchange_v1.yaml --out artifacts/demo/compiled.json
python -m dikwp_confidential_exchange.cli encrypt --sender-private identities/alice/private.json --sender-passphrase alice-pass --recipient-public identities/bob/public.json --payload artifacts/demo/compiled.json --purpose HIGH_RISK_AI_GOVERNANCE_REVIEW --out artifacts/demo/message.dce.json
python -m dikwp_confidential_exchange.cli verify --bundle artifacts/demo/message.dce.json --sender-public identities/alice/public.json
python -m dikwp_confidential_exchange.cli decrypt --recipient-private identities/bob/private.json --recipient-passphrase bob-pass --sender-public identities/alice/public.json --bundle artifacts/demo/message.dce.json --out artifacts/demo/decrypted.json
python -m dikwp_confidential_exchange.cli audit --bundle artifacts/demo/message.dce.json --out artifacts/demo/audit.json --operator demo
