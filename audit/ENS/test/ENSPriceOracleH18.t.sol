// SPDX-License-Identifier: MIT
pragma solidity ~0.8.17;

// =============================================================================
//  H18 — строгая проверка ценового оракула ENS на РЕАЛЬНОЙ связке:
//    ETHRegistrarController + StablePriceOracle + ExponentialPremiumPriceOracle
//    + Chainlink-фид.
//
//  Правила проверки (по требованию):
//   * бизнес-логика оракула НЕ подменяется — используются настоящие
//     StablePriceOracle/ExponentialPremiumPriceOracle из ens-contracts;
//   * мокается ТОЛЬКО Chainlink-фид (внешняя граница доверия), причём мы лишь
//     меняем его ДАННЫЕ (latestAnswer/updatedAt), а не оракул ENS;
//   * параметры оракула — РЕАЛЬНЫЕ mainnet-значения из
//     deploy/ethregistrar/01_deploy_exponential_premium_price_oracle.ts.
//
//  Мы разделяем два threat-model:
//   (A) PERMISSIONLESS: может ли обычный пользователь (без прав owner/feed)
//       заплатить меньше положенного или получить прибыль.
//   (B) TRUSTED-ROLE / ORACLE-TRUST: что будет, если сам Chainlink-фид врёт
//       (0, отрицательное, «протухшее», не те decimals) или owner развернул
//       оракул против неверного фида.
// =============================================================================

import "forge-std/Test.sol";

import {ETHRegistrarController} from "../vendor/ens-contracts/contracts/ethregistrar/ETHRegistrarController.sol";
import {IETHRegistrarController} from "../vendor/ens-contracts/contracts/ethregistrar/IETHRegistrarController.sol";
import {IPriceOracle} from "../vendor/ens-contracts/contracts/ethregistrar/IPriceOracle.sol";
import {BaseRegistrarImplementation} from "../vendor/ens-contracts/contracts/ethregistrar/BaseRegistrarImplementation.sol";
import {ExponentialPremiumPriceOracle} from "../vendor/ens-contracts/contracts/ethregistrar/ExponentialPremiumPriceOracle.sol";
import {AggregatorInterface} from "../vendor/ens-contracts/contracts/ethregistrar/StablePriceOracle.sol";
import {ENSRegistry} from "../vendor/ens-contracts/contracts/registry/ENSRegistry.sol";
import {ReverseRegistrar} from "../vendor/ens-contracts/contracts/reverseRegistrar/ReverseRegistrar.sol";
import {IReverseRegistrar} from "../vendor/ens-contracts/contracts/reverseRegistrar/IReverseRegistrar.sol";
import {IDefaultReverseRegistrar} from "../vendor/ens-contracts/contracts/reverseRegistrar/IDefaultReverseRegistrar.sol";

/// @dev Мок Chainlink-фида. Реализует ПОЛНУЮ форму AggregatorV3 (latestRoundData,
///      updatedAt, answeredInRound, decimals), НО оракул ENS вызывает только
///      latestAnswer() — это позволяет доказать, что ENS игнорирует все поля
///      свежести/раунда. Меняем только ДАННЫЕ фида (как если бы Chainlink обновил
///      ответ); адрес фида в оракуле ENS остаётся тем же (immutable).
contract ChainlinkFeedMock {
    int256 private _answer;
    uint256 private _updatedAt;
    uint80 private _roundId;
    uint80 private _answeredInRound;
    uint8 public decimals;

    constructor(int256 a, uint8 dec) {
        decimals = dec;
        _set(a, block.timestamp, 1, 1);
    }

    function _set(int256 a, uint256 ts, uint80 rid, uint80 arid) internal {
        _answer = a;
        _updatedAt = ts;
        _roundId = rid;
        _answeredInRound = arid;
    }

    // эмулируем нормальное обновление фида
    function set(int256 a) external {
        _set(a, block.timestamp, _roundId + 1, _roundId + 1);
    }

    // эмулируем «протухший» ответ: старый updatedAt / answeredInRound < roundId
    function setStale(int256 a, uint256 ts, uint80 rid, uint80 arid) external {
        _set(a, ts, rid, arid);
    }

    function latestAnswer() external view returns (int256) {
        return _answer;
    }

    function latestRoundData()
        external
        view
        returns (uint80, int256, uint256, uint256, uint80)
    {
        return (_roundId, _answer, _updatedAt, _updatedAt, _answeredInRound);
    }
}

contract MockDefaultReverseRegistrar2 is IDefaultReverseRegistrar {
    function setName(string calldata) external {}
    function setNameForAddr(address, string calldata) external {}
    function setNameForAddrWithSignature(
        address,
        uint256,
        string calldata,
        bytes calldata
    ) external {}
}

contract ENSPriceOracleH18Test is Test {
    // --- РЕАЛЬНЫЕ mainnet-параметры оракула ENS ---
    uint256 constant PRICE_3 = 20294266869609; // ~$640/год  (attoUSD/сек)
    uint256 constant PRICE_4 = 5073566717402; //  ~$160/год
    uint256 constant PRICE_5 = 158548959919; //   ~$5/год
    uint256 constant START_PREMIUM = 100000000000000000000000000; // $100,000,000
    uint256 constant TOTAL_DAYS = 21;
    int256 constant ETH_USD = 1600e8; // тестовый фид ENS: ETH = $1600 (8 знаков)

    uint256 constant GRACE_PERIOD = 90 days;
    uint256 constant DURATION = 28 days;
    uint256 constant MIN_COMMIT_AGE = 60;
    uint256 constant MAX_COMMIT_AGE = 86400;

    ENSRegistry ens;
    BaseRegistrarImplementation base;
    ReverseRegistrar rr;
    MockDefaultReverseRegistrar2 defaultRR;
    ChainlinkFeedMock feed;
    ExponentialPremiumPriceOracle prices;
    ETHRegistrarController controller;

    bytes32 constant ROOT = bytes32(0);
    bytes32 ETH_NODE;
    bytes32 REVERSE_NODE;

    function setUp() public {
        vm.warp(1_700_000_000);
        ETH_NODE = keccak256(abi.encodePacked(ROOT, keccak256("eth")));
        REVERSE_NODE = keccak256(abi.encodePacked(ROOT, keccak256("reverse")));

        ens = new ENSRegistry();
        base = new BaseRegistrarImplementation(ens, ETH_NODE);
        ens.setSubnodeOwner(ROOT, keccak256("eth"), address(base));

        rr = new ReverseRegistrar(ens);
        ens.setSubnodeOwner(ROOT, keccak256("reverse"), address(this));
        ens.setSubnodeOwner(REVERSE_NODE, keccak256("addr"), address(rr));

        // Chainlink-фид: ETH/USD, 8 знаков (как в проде)
        feed = new ChainlinkFeedMock(ETH_USD, 8);

        // РЕАЛЬНЫЙ оракул ENS с РЕАЛЬНЫМИ параметрами
        uint256[] memory rp = new uint256[](5);
        rp[0] = 0;
        rp[1] = 0;
        rp[2] = PRICE_3;
        rp[3] = PRICE_4;
        rp[4] = PRICE_5;
        prices = new ExponentialPremiumPriceOracle(
            AggregatorInterface(address(feed)),
            rp,
            START_PREMIUM,
            TOTAL_DAYS
        );

        defaultRR = new MockDefaultReverseRegistrar2();
        controller = new ETHRegistrarController(
            base,
            prices,
            MIN_COMMIT_AGE,
            MAX_COMMIT_AGE,
            IReverseRegistrar(address(rr)),
            IDefaultReverseRegistrar(address(defaultRR)),
            ens
        );
        base.addController(address(controller));
        rr.setController(address(controller), true);

        vm.deal(address(this), 1_000_000 ether);
    }

    receive() external payable {}

    // ---------- helpers ----------
    function _reg(
        string memory label,
        address owner
    ) internal pure returns (IETHRegistrarController.Registration memory r) {
        r = IETHRegistrarController.Registration({
            label: label,
            owner: owner,
            duration: DURATION,
            secret: bytes32(uint256(0xBEEF)),
            resolver: address(0),
            data: new bytes[](0),
            reverseRecord: 0,
            referrer: bytes32(0)
        });
    }

    function _register(string memory label, uint256 value) internal {
        IETHRegistrarController.Registration memory r = _reg(
            label,
            address(this)
        );
        controller.commit(controller.makeCommitment(r));
        vm.warp(block.timestamp + MIN_COMMIT_AGE + 1);
        controller.register{value: value}(r);
    }

    function _id(string memory label) internal pure returns (uint256) {
        return uint256(keccak256(bytes(label)));
    }

    // =====================================================================
    //  (1) PERMISSIONLESS: у пользователя НЕТ рычага влиять на цену.
    //  StablePriceOracle не имеет ни одного сеттера (все параметры immutable,
    //  usdOracle immutable). Цена — чистая функция (label, expires, duration, feed).
    // =====================================================================
    function test_permissionless_noPriceLever() public {
        // цена одинакова для любого вызывающего
        vm.prank(address(0xA11CE));
        IPriceOracle.Price memory pA = prices.price("alicexyz", 0, DURATION);
        vm.prank(address(0xB0B));
        IPriceOracle.Price memory pB = prices.price("alicexyz", 0, DURATION);
        assertEq(pA.base, pB.base, "price must not depend on caller");
        assertEq(pA.premium, pB.premium);

        // параметры действительно immutable-константы (публичные геттеры)
        assertEq(prices.price5Letter(), PRICE_5);
        assertEq(prices.price3Letter(), PRICE_3);
        assertEq(address(prices.usdOracle()), address(feed));
        // усилитель usdOracle пользователем невозможен: адрес фиксирован в
        // конструкторе; в StablePriceOracle нет функции его смены.
    }

    // =====================================================================
    //  (3) Масштабирование при 8 знаках корректно.
    //  base = attoUSD * 1e8 / answer;  answer = $/ETH * 1e8  =>  результат в wei.
    // =====================================================================
    function test_scaling_correct_8decimals() public {
        IPriceOracle.Price memory p = prices.price("fivex", 0, DURATION); // 5 букв
        uint256 expected = (PRICE_5 * DURATION * 1e8) / uint256(ETH_USD);
        assertEq(p.base, expected, "scaling formula");
        assertEq(p.premium, 0, "fresh name has no premium");
        // человеческая проверка: $5/год * 28/365 / $1600 ~= 0.000239 ETH
        assertApproxEqRel(p.base, 0.000239 ether, 0.02e18);
    }

    // =====================================================================
    //  (2)(3) Свежесть/staleness НЕ проверяется. ENS зовёт только latestAnswer():
    //  updatedAt / answeredInRound / roundId / decimals игнорируются полностью.
    //  => при «протухшем» фиде ENS продолжит считать по старому ответу.
    //  DESIGN RISK (не permissionless: пользователь не может протухнуть фид).
    // =====================================================================
    function test_staleness_isIgnored() public {
        uint256 fresh = prices.price("staley", 0, DURATION).base;

        // фид «протух» 90 дней назад, answeredInRound << roundId — но answer тот же
        feed.setStale(ETH_USD, block.timestamp - 90 days, 1000, 1);
        uint256 afterStale = prices.price("staley", 0, DURATION).base;

        assertEq(afterStale, fresh, "ENS ignores updatedAt/answeredInRound");
    }

    // =====================================================================
    //  (4) Границы grace period + экстремальная премия — end-to-end на реальном
    //  base registrar. Доказываем: НЕТ «дешёвого окна». Как только имя становится
    //  доступным (available == true), премия ~максимальна.
    // =====================================================================
    function test_gracePremiumBoundary_noCheapWindow() public {
        _register("gracey", 1 ether); // регистрируем, платим с запасом (сдача вернётся)
        uint256 id = _id("gracey");
        uint256 expires = base.nameExpires(id);

        // (a) в grace-периоде: имя недоступно, премия 0
        vm.warp(expires + GRACE_PERIOD - 1);
        assertFalse(base.available(id), "still owned during grace");
        assertEq(controller.rentPrice("gracey", DURATION).premium, 0);

        // (b) ровно на границе expires+GRACE: ещё НЕ available (strict <),
        //     но премия уже максимальна (startPremium - endValue)
        vm.warp(expires + GRACE_PERIOD);
        assertFalse(base.available(id), "boundary is strict '<'");
        uint256 premAtBoundary = controller
            .rentPrice("gracey", DURATION)
            .premium;
        // $100M / $1600 = 62 500 ETH (минус endValue) — огромная премия
        assertGt(premAtBoundary, 60000 ether, "premium ~ startPremium at open");

        // (c) первая секунда доступности: available == true, премия всё ещё ~макс
        vm.warp(expires + GRACE_PERIOD + 1);
        assertTrue(base.available(id), "now registrable");
        uint256 premFirstAvail = controller
            .rentPrice("gracey", DURATION)
            .premium;
        assertGt(premFirstAvail, 60000 ether, "no cheap window at first second");
        // премия на порядки больше base — «поймать даром» нельзя
        uint256 baseFirst = controller.rentPrice("gracey", DURATION).base;
        assertGt(premFirstAvail, baseFirst * 1_000_000);
    }

    // =====================================================================
    //  (4) Затухание премии монотонно, ограничено, без overflow/underflow,
    //  и ровно через totalDays (21) обнуляется. Проверяем реальный оракул.
    // =====================================================================
    function test_premiumDecay_monotonic_bounded_zeroAt21d() public {
        uint256 nowTs = block.timestamp;
        // expires таков, что «истекло N дней назад» = nowTs - GRACE - N*1day
        uint256 p0 = prices.price("x", nowTs - GRACE_PERIOD, DURATION).premium; // elapsed 0
        uint256 p1 = prices.price("x", nowTs - GRACE_PERIOD - 1 days, DURATION).premium;
        uint256 p10 = prices.price("x", nowTs - GRACE_PERIOD - 10 days, DURATION).premium;
        uint256 p21 = prices.price("x", nowTs - GRACE_PERIOD - 21 days, DURATION).premium;

        assertGt(p0, p1, "monotonic decreasing");
        assertGt(p1, p10, "monotonic decreasing");
        assertGt(p10, p21, "monotonic decreasing");
        assertEq(p21, 0, "premium fully decays at totalDays");

        // p0 ~ startPremium/answer; p1 ~ p0/2 (ежедневное деление пополам)
        uint256 p0AttoWei = (START_PREMIUM * 1e8) /
            uint256(ETH_USD) -
            ((START_PREMIUM >> TOTAL_DAYS) * 1e8) /
            uint256(ETH_USD);
        assertApproxEqRel(p0, p0AttoWei, 0.001e18);
        assertApproxEqRel(p1, p0 / 2, 0.02e18);
    }

    // =====================================================================
    //  (4) НУЛЕВОЙ ответ фида => деление на ноль => REVERT (DoS цены),
    //  а НЕ бесплатная регистрация. Классификация: liveness/design risk
    //  (только сам фид может отдать 0; пользователь — нет).
    // =====================================================================
    function test_zeroFeed_causesRevert_notUnderpay() public {
        feed.set(0);
        vm.expectRevert(); // division by zero в attoUSDToWei
        controller.rentPrice("zeroy", DURATION);
    }

    // =====================================================================
    //  (4)(5)(6) ОТРИЦАТЕЛЬНЫЙ ответ фида => uint256(neg) огромно => цена ~0
    //  => имя регистрируется БЕСПЛАТНО (реальный финансовый эффект, end-to-end).
    //  НО: это возможно ТОЛЬКО если Chainlink-фид отдаёт отрицательное значение.
    //  Обычный пользователь этого сделать не может => TRUSTED/ORACLE-TRUST RISK,
    //  НЕ permissionless-эксплойт.
    // =====================================================================
    function test_negativeFeed_freeRegistration_requiresFeedCompromise() public {
        // сначала честная цена > 0
        assertGt(controller.rentPrice("freey1", DURATION).base, 0);

        // фид «сломался» и отдаёт отрицательное (аварийное) значение
        feed.set(-1);
        IPriceOracle.Price memory p = controller.rentPrice("freey1", DURATION);
        assertEq(p.base, 0, "negative feed collapses base to 0");
        assertEq(p.premium, 0);

        // и тогда имя берётся даром, end-to-end через реальный контроллер
        uint256 balBefore = address(this).balance;
        _register("freey1", 0); // msg.value == 0 проходит, т.к. totalPrice == 0
        assertEq(base.ownerOf(_id("freey1")), address(this), "registered free");
        assertEq(address(this).balance, balBefore, "paid nothing");
        assertEq(address(controller).balance, 0, "protocol got 0 revenue");
    }

    // =====================================================================
    //  (4) НЕВЕРНЫЕ decimals фида (18 вместо 8) => недоплата в 1e10 раз.
    //  Оракул хардкодит масштаб 1e8 и НЕ читает feed.decimals(). Но чтобы это
    //  «выстрелило», owner/governance должен развернуть оракул против фида с
    //  другими decimals. Классификация: TRUSTED-ROLE (deploy-time) RISK.
    // =====================================================================
    function test_wrongDecimalsFeed_underpay_isDeployTimeTrustedRole() public {
        // корректный фид (8 знаков) -> корректная база
        uint256 correctBase = prices.price("decy", 0, DURATION).base;

        // тот же ETH=$1600, но фид сообщает 18 знаков (1600e18). Оракул ENS
        // по-прежнему делит на 1e8 -> цена занижена в 1e10 раз.
        ChainlinkFeedMock feed18 = new ChainlinkFeedMock(1600e18, 18);
        uint256[] memory rp = new uint256[](5);
        rp[0] = 0;
        rp[1] = 0;
        rp[2] = PRICE_3;
        rp[3] = PRICE_4;
        rp[4] = PRICE_5;
        ExponentialPremiumPriceOracle badPrices = new ExponentialPremiumPriceOracle(
                AggregatorInterface(address(feed18)),
                rp,
                START_PREMIUM,
                TOTAL_DAYS
            );
        uint256 wrongBase = badPrices.price("decy", 0, DURATION).base;

        // ~1e10-кратная недоплата (точное равенство недостижимо из-за усечения
        // целочисленного деления при 18 знаках — сверяем с относит. допуском)
        assertApproxEqRel(
            wrongBase * 1e10,
            correctBase,
            0.0001e18,
            "18-dec feed underprices ~1e10x"
        );
        assertLt(wrongBase, correctBase, "massive underpayment if misconfigured");
    }
}
