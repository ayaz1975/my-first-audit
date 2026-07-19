// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test, console2} from "forge-std/Test.sol";

/// @dev Минимальный интерфейс к IdleCDOTranche. Сам контракт закреплён на
///      solidity =0.8.10, а forge-std требует >=0.8.13 — pragma несовместимы.
///      Поэтому мы не импортируем .sol напрямую, а деплоим артефакт через
///      deployCode и общаемся через этот интерфейс.
interface IIdleCDOTranche {
    function minter() external view returns (address);
    function mint(address account, uint256 amount) external;
    function burn(address account, uint256 amount) external;
    function balanceOf(address account) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
    function totalSupply() external view returns (uint256);
}

/// @dev Тесты к IdleCDOTranche.sol.
///      В самом контракте НЕТ прямой уязвимости кражи средств: mint/burn
///      закрыты проверкой `msg.sender == minter`. Настоящий риск — это
///      ЦЕНТРАЛИЗАЦИЯ: minter (контракт IdleCDO) имеет абсолютную власть.
///      Эти тесты доказывают, на что способен minter, и что вся безопасность
///      держится ровно на одном require. Проходящий тест = поведение реально
///      достижимо в mainnet.
contract IdleCDOTrancheHack is Test {
    IIdleCDOTranche tranche;

    // Деплоер транша = minter. В проде это контракт IdleCDO (в initialize).
    // Здесь address(this) деплоит артефакт, значит minter = address(this).
    address minter = address(this);

    address alice = address(0xA11CE);        // честный держатель транша
    address bob = address(0xB0B);            // ещё держатель
    address attackerWallet = address(0xBAD); // куда уводится эмиссия
    address stranger = address(0x5723A6);    // посторонний, не minter

    function setUp() public {
        // IdleCDOTranche.sol компилируется своим solc (0.8.10), деплоим байткод.
        // constructor(string _name, string _symbol) -> minter = msg.sender.
        tranche = IIdleCDOTranche(
            deployCode("IdleCDOTranche.sol:IdleCDOTranche", abi.encode("Idle DAI Senior", "AA_IdleDAI"))
        );

        // Раздаём токены транша, как после депозитов пользователей.
        tranche.mint(alice, 10_000e18);
        tranche.mint(bob, 5_000e18);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ПРОВЕРКА ЗАЩИТЫ: посторонний НЕ может майнить/жечь.
    // Показывает, что единственная линия обороны — require(msg.sender==minter).
    // ─────────────────────────────────────────────────────────────────────────
    function test_AccessControl_StrangerCannotMintOrBurn() public {
        vm.prank(stranger);
        vm.expectRevert("TRANCHE:!AUTH");
        tranche.mint(stranger, 1e18);

        vm.prank(stranger);
        vm.expectRevert("TRANCHE:!AUTH");
        tranche.burn(alice, 1e18);

        console2.log(unicode"OK: посторонний отбит проверкой авторизации");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // РИСК #1 (CENTRALIZATION / HIGH): minter жжёт токены ЛЮБОГО адреса
    // без allowance и без согласия владельца. Это не burnFrom — approve не нужен.
    // Если IdleCDO скомпрометирован — балансы всех держателей можно обнулить.
    // ─────────────────────────────────────────────────────────────────────────
    function test_Exploit_MinterBurnsAnyUserWithoutApproval() public {
        assertEq(tranche.balanceOf(alice), 10_000e18);

        // Alice НИЧЕГО не подписывала и не давала allowance.
        assertEq(tranche.allowance(alice, minter), 0, unicode"allowance = 0");

        vm.prank(minter);
        tranche.burn(alice, 10_000e18);

        assertEq(tranche.balanceOf(alice), 0, unicode"ЭКСПЛОЙТ: баланс Alice сожжён minter'ом");
        console2.log("Alice balance after minter burn:", tranche.balanceOf(alice));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // РИСК #2 (CENTRALIZATION / HIGH): бесконтрольная эмиссия.
    // minter печатает себе больше, чем весь supply, размывая доли всех.
    // ─────────────────────────────────────────────────────────────────────────
    function test_Exploit_UnlimitedMintDilution() public {
        uint256 supplyBefore = tranche.totalSupply();

        uint256 minted = supplyBefore * 1000;
        vm.prank(minter);
        tranche.mint(attackerWallet, minted);

        assertEq(tranche.balanceOf(attackerWallet), minted, unicode"ЭКСПЛОЙТ: напечатано из воздуха");
        assertGt(tranche.totalSupply(), supplyBefore, unicode"supply вырос без ограничений");

        console2.log("supply before:", supplyBefore);
        console2.log("supply after :", tranche.totalSupply());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // РИСК #3 (INFORMATIONAL): minter невозможно сменить или обнулить.
    // Нет setMinter/renounce. Кто задеплоил транш — тот навсегда всесилен.
    // ВЫВОД для аудита: критично проверить в IdleCDO, что транш создаётся
    // им самим через `new IdleCDOTranche(...)`, иначе minter'ом станет
    // чужой адрес, задеплоивший контракт.
    // ─────────────────────────────────────────────────────────────────────────
    function test_Design_MinterIsFixedForever() public view {
        assertEq(tranche.minter(), address(this), unicode"minter зафиксирован деплоером");
        // Функции смены minter в ABI просто нет — менять нечего.
    }
}
