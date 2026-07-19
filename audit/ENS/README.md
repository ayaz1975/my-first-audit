# Аудит ENS `ETHRegistrarController` — PoC

Foundry-harness, который прогоняет **реальный, немодифицированный** контракт
`ETHRegistrarController` из
[`ensdomains/ens-contracts`](https://github.com/ensdomains/ens-contracts)
(`contracts/ethregistrar/ETHRegistrarController.sol`, Solidity `~0.8.17`, HEAD)
вместе с реальными зависимостями:

- `ENSRegistry` (реестр)
- `BaseRegistrarImplementation` (ERC-721 для `.eth`)
- `ReverseRegistrar` (reverse для coinType 60)
- `StablePriceOracle` + `DummyOracle` (цена)

Копия контроллера в `src/ETHRegistrarController.sol` этого репозитория —
**байт-в-байт** идентична исходнику ENS (проверено `diff`).

Логика контрактов не изменяется. `defaultReverseRegistrar` заменён минимальным
моком (`MockDefaultReverseRegistrar`), потому что путь `REVERSE_RECORD_DEFAULT_BIT`
в эксплойте не задействован, а реальный `DefaultReverseRegistrar` тянет OZ v5.

## Запуск

```bash
cd audit/ENS
./vendor.sh          # разово: клонирует ens-contracts + OZ v4.9.3 + forge-std в ./vendor
forge test -vv
```

Ожидается: **14 тестов проходят** (2 набора).

## Наборы

- `test/ENSControllerReentrancy.t.sol` — H1 (reentrancy) + H17 (reverse-record).
- `test/ENSPriceOracleH18.t.sol` — H18: реальный `ExponentialPremiumPriceOracle`
  + мок только Chainlink-фида, реальные mainnet-параметры оракула.

## Что проверяет каждый тест

| Тест | Гипотеза | Вердикт |
|------|----------|---------|
| `test_control_registration_resolverZeroPath_andRefund` | базовая линия: реальная регистрация + возврат сдачи | контроль (работает, сдача точная) |
| `test_control_registration_withResolver_benign` | базовая линия: setRecord + multicall + transferFrom + reverse | контроль (работает, сдача точная) |
| `test_confirmed_reverseRecordBoundToMsgSenderNotOwner` | H-reverse: при `owner != msg.sender` reverse ставится на плательщика | **подтверждено** (функциональный дефект, не кража) |
| `test_reentrancy_viaReverseSetName_cannotRegisterFree` | H1-a: reentrancy через `resolver.setName` | **опровергнуто** |
| `test_reentrancy_viaResolverMulticall_cannotRegisterFree` | H1-b: reentrancy через `resolver.multicallWithNodeCheck` | **опровергнуто** |
| `test_reentrancy_viaWithdraw_isSelfDefeating` | H1-c: reentrancy → `withdraw()` в разгар `register()` | **опровергнуто** (полный откат) |
| `test_permissionless_noPriceLever` | H18: у пользователя нет рычага цены (всё immutable) | **опровергнуто** (нет permissionless-атаки) |
| `test_scaling_correct_8decimals` | H18: масштабирование при 8 знаках | корректно |
| `test_staleness_isIgnored` | H18: свежесть Chainlink не проверяется | **design risk** |
| `test_gracePremiumBoundary_noCheapWindow` | H18: границы grace + экстремальная премия | безопасно (нет дешёвого окна) |
| `test_premiumDecay_monotonic_bounded_zeroAt21d` | H18: затухание премии | безопасно (монотонно, →0 за 21д) |
| `test_zeroFeed_causesRevert_notUnderpay` | H18: нулевой ответ фида | **design risk** (DoS, не недоплата) |
| `test_negativeFeed_freeRegistration_requiresFeedCompromise` | H18: отрицательный ответ → бесплатно | **oracle-trust risk** (не permissionless) |
| `test_wrongDecimalsFeed_underpay_isDeployTimeTrustedRole` | H18: неверные decimals фида | **trusted-role** (deploy-time) |

## Вердикт H18

Для здорового 8-значного ETH/USD-фида **permissionless-атаки нет**: параметры
оракула и адрес фида `immutable`, у пользователя ноль рычагов. Все сценарии с
финансовым эффектом (0 → DoS, отрицательное → бесплатно, не те decimals →
недоплата) требуют либо сбоя самого Chainlink-фида (oracle-trust), либо
неверной конфигурации при деплое (trusted-role). Плюс отсутствует проверка
staleness/`answeredInRound`/`decimals` (`AggregatorInterface` знает только
`latestAnswer()`). Итог: **design risk**, не уязвимость permissionless.

## Почему H1 (reentrancy) безопасна

1. **CEI**: `commitments[commitment]` удаляется, а имя минтится в base registrar
   **до** любых внешних вызовов (`multicall`, `setName`).
2. **Возврат сдачи — последним** и через `.transfer` (2300 газа) → классический
   reentrancy на возврате невозможен.
3. **Нет хука receiver**: контроллер использует `transferFrom`, а не
   `safeTransferFrom`, поэтому `onERC721Received` не вызывается.
4. **Реентрантный `register` требует своей оплаты**: вложенный вызов идёт с
   `msg.value == 0` и падает на `InsufficientValue` ещё до проверки commitment.
5. **`withdraw()` платит только `owner()`**: даже вызванный реентрантно, он не
   отправляет средства атакующему; при наличии сдачи внешняя транзакция вообще
   откатывается целиком.
