#!/usr/bin/env bash
# Вендорит точные зависимости, нужные чтобы скомпилировать РЕАЛЬНЫЙ ENS
# ETHRegistrarController и прогнать PoC. Идемпотентно: уже присутствующее пропускается.
#
#   ensdomains/ens-contracts       -> реальный контроллер + registry + base registrar
#                                     + reverse registrar + price oracle
#   OpenZeppelin v4.9.3            -> ровно та версия OZ, на которой компилируется
#                                     контроллер и его зависимости (Ownable/ERC721/IERC20/ERC165)
#
# Замечание: DefaultReverseRegistrar и L2-реверсы в ens-contracts тянут OZ v5
# (@openzeppelin/contracts-v5). Они НЕ входят в путь эксплойта и в PoC заменены
# минимальным моком IDefaultReverseRegistrar, поэтому OZ v5 здесь не вендорится.
#
# Usage:  cd audit/ENS && ./vendor.sh && forge test -vv
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p vendor

if [ ! -d vendor/ens-contracts ]; then
  echo ">> cloning ensdomains/ens-contracts ..."
  git clone --depth 1 https://github.com/ensdomains/ens-contracts.git vendor/ens-contracts
else
  echo ">> vendor/ens-contracts already present, skipping"
fi

if [ ! -d vendor/openzeppelin-4.9.3 ]; then
  echo ">> cloning OpenZeppelin contracts v4.9.3 ..."
  git clone --depth 1 --branch v4.9.3 \
    https://github.com/OpenZeppelin/openzeppelin-contracts.git vendor/openzeppelin-4.9.3
else
  echo ">> vendor/openzeppelin-4.9.3 already present, skipping"
fi

if [ ! -d vendor/forge-std ]; then
  echo ">> cloning foundry-rs/forge-std ..."
  git clone --depth 1 https://github.com/foundry-rs/forge-std.git vendor/forge-std
else
  echo ">> vendor/forge-std already present, skipping"
fi

echo ">> done. Now run: forge test -vv"
