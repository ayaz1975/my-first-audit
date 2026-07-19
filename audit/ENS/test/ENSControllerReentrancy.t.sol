// SPDX-License-Identifier: MIT
pragma solidity ~0.8.17;

// =============================================================================
//  Аудит реального ENS `ETHRegistrarController` (ensdomains/ens-contracts @ HEAD).
//
//  Контракт под тестом НЕ модифицируется. Мы поднимаем реальный набор контрактов
//  ENS (ENSRegistry, BaseRegistrarImplementation, ReverseRegistrar,
//  StablePriceOracle + DummyOracle) и реальный ETHRegistrarController, связываем
//  их так же, как в проде, и прогоняем гипотезы.
//
//  Самая сильная гипотеза (H1): reentrancy через подконтрольный атакующему
//  resolver / reverse registrar позволяет украсть ETH, получить двойной возврат
//  или зарегистрировать имя бесплатно.  Ниже — исполняемое доказательство того,
//  что это НЕВОЗМОЖНО (гипотеза ОПРОВЕРГНУТА), плюс подтверждённое побочное
//  наблюдение о reverse-записи (H-reverse).
// =============================================================================

import "forge-std/Test.sol";

import {ETHRegistrarController} from "../vendor/ens-contracts/contracts/ethregistrar/ETHRegistrarController.sol";
import {IETHRegistrarController} from "../vendor/ens-contracts/contracts/ethregistrar/IETHRegistrarController.sol";
import {IPriceOracle} from "../vendor/ens-contracts/contracts/ethregistrar/IPriceOracle.sol";
import {BaseRegistrarImplementation} from "../vendor/ens-contracts/contracts/ethregistrar/BaseRegistrarImplementation.sol";
import {StablePriceOracle, AggregatorInterface} from "../vendor/ens-contracts/contracts/ethregistrar/StablePriceOracle.sol";
import {DummyOracle} from "../vendor/ens-contracts/contracts/ethregistrar/DummyOracle.sol";
import {ENSRegistry} from "../vendor/ens-contracts/contracts/registry/ENSRegistry.sol";
import {ENS} from "../vendor/ens-contracts/contracts/registry/ENS.sol";
import {ReverseRegistrar} from "../vendor/ens-contracts/contracts/reverseRegistrar/ReverseRegistrar.sol";
import {IReverseRegistrar} from "../vendor/ens-contracts/contracts/reverseRegistrar/IReverseRegistrar.sol";
import {IDefaultReverseRegistrar} from "../vendor/ens-contracts/contracts/reverseRegistrar/IDefaultReverseRegistrar.sol";

// -----------------------------------------------------------------------------
//  Мок только для defaultReverseRegistrar: путь REVERSE_RECORD_DEFAULT_BIT в PoC
//  не задействуется (мы бьём по ETH-биту и по multicall). Реальный
//  DefaultReverseRegistrar тянет OZ v5 и не влияет на тестируемую логику.
// -----------------------------------------------------------------------------
contract MockDefaultReverseRegistrar is IDefaultReverseRegistrar {
    function setName(string calldata) external {}
    function setNameForAddr(address, string calldata) external {}
    function setNameForAddrWithSignature(
        address,
        uint256,
        string calldata,
        bytes calldata
    ) external {}
}

// -----------------------------------------------------------------------------
//  Атакующий контракт. Он одновременно:
//    * регистрант (msg.sender для register), поэтому держит ETH;
//    * resolver регистрации (address совпадает), поэтому получает управление
//      в двух точках реального контроллера:
//        1) Resolver(resolver).multicallWithNodeCheck(...)  — если data != пусто;
//        2) reverseRegistrar.setNameForAddr(...) -> resolver.setName(...) — если
//           взведён REVERSE_RECORD_ETHEREUM_BIT.
//    * получатель токена (transferFrom без safe -> хука receiver НЕТ).
// -----------------------------------------------------------------------------
contract Attacker {
    enum Mode {
        NONE, // просто фиксируем факт коллбэка (для benign / reverse-binding)
        REGISTER, // пробуем зарегистрировать второе имя бесплатно (msg.value=0)
        WITHDRAW // пробуем вывести баланс контроллера во время register
    }

    ETHRegistrarController public immutable controller;
    Mode public mode;
    bool public reentered;
    bool public innerReverted;

    IETHRegistrarController.Registration innerReg;
    // node => name, чтобы наблюдать, ЧЬЮ reverse-запись выставил контроллер
    mapping(bytes32 => string) public recordedName;

    constructor(ETHRegistrarController _c) {
        controller = _c;
    }

    function setMode(Mode m) external {
        mode = m;
    }

    function setInnerReg(
        IETHRegistrarController.Registration calldata r
    ) external {
        innerReg = r;
    }

    function commitFor(
        IETHRegistrarController.Registration calldata r
    ) external {
        controller.commit(controller.makeCommitment(r));
    }

    function registerFor(
        IETHRegistrarController.Registration calldata r,
        uint256 value
    ) external {
        controller.register{value: value}(r);
    }

    function _onReenter() internal {
        reentered = true;
        if (mode == Mode.REGISTER) {
            // Попытка зарегистрировать ВТОРОЕ имя, ничего не заплатив.
            try controller.register{value: 0}(innerReg) {
                // если это когда-нибудь пройдёт — деньги/имя украдены
            } catch {
                innerReverted = true;
            }
        } else if (mode == Mode.WITHDRAW) {
            // Попытка увести средства контроллера в разгар register().
            controller.withdraw();
        }
    }

    // Коллбэк из ReverseRegistrar (resolver.setName)
    function setName(bytes32 node, string calldata name) external {
        recordedName[node] = name;
        _onReenter();
    }

    // Коллбэк из контроллера (resolver.multicallWithNodeCheck)
    function multicallWithNodeCheck(
        bytes32,
        bytes[] calldata
    ) external returns (bytes[] memory) {
        _onReenter();
        return new bytes[](0);
    }

    receive() external payable {}
}

contract ENSControllerReentrancyTest is Test {
    // --- реальные контракты ENS ---
    ENSRegistry ens;
    BaseRegistrarImplementation base;
    ReverseRegistrar rr;
    MockDefaultReverseRegistrar defaultRR;
    DummyOracle oracle;
    StablePriceOracle prices;
    ETHRegistrarController controller;

    // --- namehashes ---
    bytes32 constant ROOT = bytes32(0);
    bytes32 ETH_NODE; // namehash('eth')
    bytes32 REVERSE_NODE; // namehash('reverse')
    bytes32 ADDR_REVERSE_NODE; // namehash('addr.reverse')

    uint256 constant MIN_COMMIT_AGE = 60;
    uint256 constant MAX_COMMIT_AGE = 86400; // 24h
    uint256 constant DURATION = 28 days; // == MIN_REGISTRATION_DURATION

    function setUp() public {
        // block.timestamp по умолчанию = 1; конструктор контроллера требует
        // maxCommitmentAge <= block.timestamp, поэтому сдвигаем время вперёд.
        vm.warp(1_700_000_000);

        ETH_NODE = keccak256(abi.encodePacked(ROOT, keccak256("eth")));
        REVERSE_NODE = keccak256(abi.encodePacked(ROOT, keccak256("reverse")));
        ADDR_REVERSE_NODE = keccak256(
            abi.encodePacked(REVERSE_NODE, keccak256("addr"))
        );
        // sanity: совпадает с константой внутри ReverseRegistrar
        assertEq(
            ADDR_REVERSE_NODE,
            0x91d1777781884d03a6757a803996e38de2a42967fb37eeaca72729271025a9e2
        );

        // 1) Реестр. Конструктор делает records[0x0].owner = msg.sender (= этот тест).
        ens = new ENSRegistry();

        // 2) Base registrar для .eth
        base = new BaseRegistrarImplementation(ens, ETH_NODE);
        // отдать узел 'eth' во владение base (нужно для модификатора live)
        ens.setSubnodeOwner(ROOT, keccak256("eth"), address(base));

        // 3) Reverse registrar + дерево addr.reverse
        rr = new ReverseRegistrar(ens);
        ens.setSubnodeOwner(ROOT, keccak256("reverse"), address(this));
        ens.setSubnodeOwner(REVERSE_NODE, keccak256("addr"), address(rr));

        // 4) Оракул цены: ETH = $2000 (8 знаков), 5+ букв ~ $5/год
        oracle = new DummyOracle(2000e8);
        uint256[] memory rp = new uint256[](5);
        rp[0] = 0; // 1 буква (не используется)
        rp[1] = 0; // 2 буквы (не используется)
        rp[2] = 158548959918; // 3 буквы
        rp[3] = 158548959918; // 4 буквы
        rp[4] = 158548959918; // 5+ букв (~$5/год в attoUSD/сек)
        prices = new StablePriceOracle(
            AggregatorInterface(address(oracle)),
            rp
        );

        // 5) Default reverse — мок (вне пути эксплойта)
        defaultRR = new MockDefaultReverseRegistrar();

        // 6) Реальный контроллер
        controller = new ETHRegistrarController(
            base,
            prices,
            MIN_COMMIT_AGE,
            MAX_COMMIT_AGE,
            IReverseRegistrar(address(rr)),
            IDefaultReverseRegistrar(address(defaultRR)),
            ens
        );

        // 7) Полномочия: контроллер регистрирует в base и ставит reverse
        base.addController(address(controller));
        rr.setController(address(controller), true);
    }

    receive() external payable {}

    // ---- helpers ----------------------------------------------------------

    function _reg(
        string memory label,
        address owner,
        address resolver,
        uint8 reverseRecord,
        bool withData
    ) internal pure returns (IETHRegistrarController.Registration memory r) {
        bytes[] memory data;
        if (withData) {
            data = new bytes[](1);
            data[0] = hex"deadbeef"; // произвольные данные -> сработает multicall
        }
        r = IETHRegistrarController.Registration({
            label: label,
            owner: owner,
            duration: DURATION,
            secret: bytes32(uint256(0xA11CE)),
            resolver: resolver,
            data: data,
            reverseRecord: reverseRecord,
            referrer: bytes32(0)
        });
    }

    function _total(string memory label) internal view returns (uint256) {
        IPriceOracle.Price memory p = controller.rentPrice(label, DURATION);
        return p.base + p.premium;
    }

    function _labelhash(string memory label) internal pure returns (uint256) {
        return uint256(keccak256(bytes(label)));
    }

    // =====================================================================
    //  КОНТРОЛЬ 1: обычная регистрация (resolver = 0) на реальном контракте.
    //  Заодно проверяем возврат лишнего ETH.
    // =====================================================================
    function test_control_registration_resolverZeroPath_andRefund() public {
        IETHRegistrarController.Registration memory r = _reg(
            "alicexyz",
            address(this),
            address(0),
            0,
            false
        );

        controller.commit(controller.makeCommitment(r));
        vm.warp(block.timestamp + MIN_COMMIT_AGE + 1);

        uint256 total = _total("alicexyz");
        assertGt(total, 0, "price must be > 0");

        uint256 balBefore = address(this).balance;
        controller.register{value: total + 1 ether}(r);

        // имя зарегистрировано на реальном base registrar
        assertEq(base.ownerOf(_labelhash("alicexyz")), address(this));
        assertGt(base.nameExpires(_labelhash("alicexyz")), block.timestamp);
        // в resolver=0 ветке base сам пишет владельца узла в реестр
        assertEq(
            ens.owner(
                keccak256(abi.encodePacked(ETH_NODE, keccak256("alicexyz")))
            ),
            address(this)
        );

        // возврат: заплатили РОВНО total, излишек вернулся
        assertEq(address(this).balance, balBefore - total, "exact refund");
        assertEq(address(controller).balance, total, "controller keeps fee");
    }

    // =====================================================================
    //  КОНТРОЛЬ 2: регистрация с resolver + data + reverse (benign),
    //  чтобы честно пройти setRecord + multicall + transferFrom + reverse.
    //  Никакого reentrancy — базовая линия «всё работает и возвращает сдачу».
    // =====================================================================
    function test_control_registration_withResolver_benign() public {
        Attacker res = new Attacker(controller); // mode == NONE
        vm.deal(address(res), 5 ether);

        IETHRegistrarController.Registration memory r = _reg(
            "bobxyzzy",
            address(res),
            address(res),
            1, // ETH reverse bit
            true // data != пусто -> multicall тоже вызовется
        );

        res.commitFor(r);
        vm.warp(block.timestamp + MIN_COMMIT_AGE + 1);

        uint256 total = _total("bobxyzzy");
        uint256 balBefore = address(res).balance;
        res.registerFor(r, total + 0.3 ether);

        assertTrue(res.reentered(), "resolver callbacks must fire");
        assertEq(base.ownerOf(_labelhash("bobxyzzy")), address(res));
        assertEq(address(res).balance, balBefore - total, "exact refund");
        assertEq(address(controller).balance, total);
    }

    // =====================================================================
    //  H-reverse (ПОДТВЕРЖДЕНО): при owner != msg.sender контроллер выставляет
    //  primary-name (reverse) на MSG.SENDER (плательщика), а НЕ на owner.
    //  Это делает reverse-запись некорректной/вводящей в заблуждение, когда
    //  регистрируют «в пользу» другого адреса. Не кража средств, но
    //  функциональный дефект соответствия forward/reverse.
    // =====================================================================
    function test_confirmed_reverseRecordBoundToMsgSenderNotOwner() public {
        Attacker payer = new Attacker(controller); // выступает и как resolver
        vm.deal(address(payer), 5 ether);
        address victimOwner = address(0xB0B);

        IETHRegistrarController.Registration memory r = _reg(
            "carolxyz",
            victimOwner, // владелец имени — другой адрес
            address(payer), // resolver
            1, // ETH reverse bit
            false
        );

        payer.commitFor(r);
        vm.warp(block.timestamp + MIN_COMMIT_AGE + 1);
        payer.registerFor(r, _total("carolxyz") + 0.1 ether);

        // forward-владелец имени — victimOwner
        assertEq(base.ownerOf(_labelhash("carolxyz")), victimOwner);

        // reverse-запись выставлена на плательщика (payer), НЕ на victimOwner
        bytes32 payerReverseNode = rr.node(address(payer));
        bytes32 victimReverseNode = rr.node(victimOwner);
        assertEq(
            payer.recordedName(payerReverseNode),
            "carolxyz.eth",
            "reverse bound to msg.sender"
        );
        assertEq(
            bytes(payer.recordedName(victimReverseNode)).length,
            0,
            "owner got NO reverse record"
        );
        // владелец reverse-узла в реестре — тоже payer, не owner
        assertEq(ens.owner(payerReverseNode), address(payer));
    }

    // =====================================================================
    //  H1-a (ОПРОВЕРГНУТО): reentrancy через resolver.setName в reverse-ветке
    //  НЕ даёт зарегистрировать второе имя бесплатно.
    // =====================================================================
    function test_reentrancy_viaReverseSetName_cannotRegisterFree() public {
        Attacker atk = new Attacker(controller);
        vm.deal(address(atk), 5 ether);

        IETHRegistrarController.Registration memory outer = _reg(
            "reenter1",
            address(atk),
            address(atk),
            1, // ETH reverse bit -> resolver.setName коллбэк
            false
        );
        // второе имя, которое атакующий пытается получить даром при реентранси
        IETHRegistrarController.Registration memory inner = _reg(
            "secondx",
            address(atk),
            address(0),
            0,
            false
        );

        atk.setMode(Attacker.Mode.REGISTER);
        atk.setInnerReg(inner);
        atk.commitFor(outer);
        vm.warp(block.timestamp + MIN_COMMIT_AGE + 1);

        uint256 total = _total("reenter1");
        uint256 balBefore = address(atk).balance;
        atk.registerFor(outer, total + 0.2 ether);

        // коллбэк реально сработал (не вакуумный тест) и реентрант-register упал
        assertTrue(atk.reentered(), "callback must fire");
        assertTrue(atk.innerReverted(), "inner free register must revert");

        // внешнее имя зарегистрировано; ВТОРОЕ — нет
        assertEq(base.ownerOf(_labelhash("reenter1")), address(atk));
        assertTrue(controller.available("secondx"), "second name NOT taken");

        // деньги сохранены: заплачено ровно total, излишек возвращён
        assertEq(address(atk).balance, balBefore - total, "exact refund");
        assertEq(address(controller).balance, total, "no drain");
    }

    // =====================================================================
    //  H1-b (ОПРОВЕРГНУТО): reentrancy через resolver.multicallWithNodeCheck
    //  (вторая точка внешнего вызова) — тот же результат.
    // =====================================================================
    function test_reentrancy_viaResolverMulticall_cannotRegisterFree() public {
        Attacker atk = new Attacker(controller);
        vm.deal(address(atk), 5 ether);

        IETHRegistrarController.Registration memory outer = _reg(
            "reenter2",
            address(atk),
            address(atk),
            0, // без reverse
            true // data != пусто -> multicall коллбэк
        );
        IETHRegistrarController.Registration memory inner = _reg(
            "secondy",
            address(atk),
            address(0),
            0,
            false
        );

        atk.setMode(Attacker.Mode.REGISTER);
        atk.setInnerReg(inner);
        atk.commitFor(outer);
        vm.warp(block.timestamp + MIN_COMMIT_AGE + 1);

        uint256 total = _total("reenter2");
        uint256 balBefore = address(atk).balance;
        atk.registerFor(outer, total + 0.2 ether);

        assertTrue(atk.reentered(), "multicall callback must fire");
        assertTrue(atk.innerReverted(), "inner free register must revert");
        assertEq(base.ownerOf(_labelhash("reenter2")), address(atk));
        assertTrue(controller.available("secondy"), "second name NOT taken");
        assertEq(address(atk).balance, balBefore - total, "exact refund");
        assertEq(address(controller).balance, total, "no drain");
    }

    // =====================================================================
    //  H1-c (ОПРОВЕРГНУТО): reentrancy-вызов withdraw() в разгар register()
    //  самоубийственен — внешняя транзакция откатывается целиком (CEI + порядок
    //  возврата сдачи через .transfer). Средства НЕ теряются, имя НЕ создаётся.
    // =====================================================================
    function test_reentrancy_viaWithdraw_isSelfDefeating() public {
        Attacker atk = new Attacker(controller);
        vm.deal(address(atk), 5 ether);

        IETHRegistrarController.Registration memory outer = _reg(
            "reenter3",
            address(atk),
            address(atk),
            1, // ETH reverse -> setName коллбэк, где вызовем withdraw()
            false
        );

        atk.setMode(Attacker.Mode.WITHDRAW);
        atk.commitFor(outer);
        vm.warp(block.timestamp + MIN_COMMIT_AGE + 1);

        uint256 total = _total("reenter3");
        uint256 atkBalBefore = address(atk).balance;
        uint256 ownerBalBefore = address(this).balance; // owner() контроллера = этот тест

        // излишек > 0 -> на выходе register() дойдёт до payable(msg.sender).transfer,
        // но баланс уже уведён withdraw() -> transfer падает -> весь register откатывается.
        vm.expectRevert();
        atk.registerFor(outer, total + 0.2 ether);

        // полный откат: имя не создано, средства целы
        assertTrue(controller.available("reenter3"), "name NOT registered");
        assertEq(address(atk).balance, atkBalBefore, "attacker funds intact");
        assertEq(address(controller).balance, 0, "controller empty");
        assertEq(address(this).balance, ownerBalBefore, "owner unchanged");
    }
}
