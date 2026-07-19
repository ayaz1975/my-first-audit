#!/usr/bin/env bash
# Vendors the exact dependencies needed to compile the REAL L1Staking contract
# and run the audit PoCs. Idempotent: skips anything already present.
#
#   graphprotocol/contracts  -> real L1Staking + Staking + Controller + libs
#   OpenZeppelin v3.4.2       -> SafeMath/ECDSA as used by Solidity 0.7.6 code
#
# Usage:  cd audit/L1Staking && ./vendor.sh && forge test
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p vendor

if [ ! -d vendor/graphprotocol ]; then
  echo ">> cloning graphprotocol/contracts ..."
  git clone --depth 1 https://github.com/graphprotocol/contracts.git vendor/graphprotocol
else
  echo ">> vendor/graphprotocol already present, skipping"
fi

if [ ! -d vendor/openzeppelin-3.4.2 ]; then
  echo ">> cloning OpenZeppelin contracts v3.4.2 ..."
  git clone --depth 1 --branch v3.4.2 \
    https://github.com/OpenZeppelin/openzeppelin-contracts.git vendor/openzeppelin-3.4.2
else
  echo ">> vendor/openzeppelin-3.4.2 already present, skipping"
fi

echo ">> done. Now run: forge test"
