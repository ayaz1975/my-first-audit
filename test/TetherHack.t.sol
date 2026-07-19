// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test, console2} from "forge-std/Test.sol";

/// @dev Минимальный интерфейс к TetherToken. Сам контракт написан на solidity 0.4.17,
///      поэтому напрямую его не импортируем (несовместимые pragma), а деплоим
///      скомпилированный артефакт через deployCode и общаемся через этот интерфейс.
///      Обрати внимание: transfer/approve в TetherToken НЕ возвращают bool (это и есть
///      известный баг USDT), поэтому в интерфейсе объявляем их без возвращаемого значения —
///      иначе ABI-декодер словил бы revert на пустом returndata.
interface ITetherToken {
    function totalSupply() external view returns (uint256);
    function decimals() external view returns (uint256);
    function balanceOf(address who) external view returns (uint256);
    function transfer(address to, uint256 value) external; // без bool — как в оригинале
    function isBlackListed(address who) external view returns (bool);
    function addBlackList(address evilUser) external;       // onlyOwner
    function destroyBlackFunds(address blackListedUser) external; // onlyOwner
}

contract TetherHack is Test {
    ITetherToken usdt;

    address owner = address(this);      // деплоер получает весь totalSupply и становится owner
    address victim = address(0xC1C7); // обычный держатель токенов

    uint256 constant DECIMALS = 6;
    uint256 constant INITIAL_SUPPLY = 1_000_000 * 10 ** DECIMALS; // 1M USDT

    function setUp() public {
        // Конструктор: TetherToken(uint _initialSupply, string _name, string _symbol, uint _decimals)
        bytes memory args = abi.encode(INITIAL_SUPPLY, "Tether USD", "USDT", DECIMALS);
        usdt = ITetherToken(deployCode("TetherToken.sol:TetherToken", args));

        // Owner раздаёт часть токенов обычному пользователю.
        usdt.transfer(victim, 100_000 * 10 ** DECIMALS); // 100k USDT
    }

    /// @notice Доказательство находки №1: owner может БЕЗВОЗВРАТНО обнулить чужой баланс.
    ///         destroyBlackFunds меняет и баланс жертвы, и глобальный _totalSupply.
    function test_OwnerCanConfiscateUserFunds() public {
        uint256 supplyBefore = usdt.totalSupply();
        uint256 victimBefore = usdt.balanceOf(victim);

        // Исходное состояние: у жертвы честно лежат 100k USDT.
        assertEq(victimBefore, 100_000 * 10 ** DECIMALS, "victim holds 100k USDT");
        assertFalse(usdt.isBlackListed(victim), "victim not blacklisted yet");

        // --- ДЕЙСТВИЯ OWNER ---
        // Шаг 1: owner заносит жертву в чёрный список (destroyBlackFunds требует этого).
        usdt.addBlackList(victim);
        assertTrue(usdt.isBlackListed(victim), "victim is now blacklisted");

        // Шаг 2: owner уничтожает средства жертвы одним вызовом.
        usdt.destroyBlackFunds(victim);

        // --- РЕЗУЛЬТАТ ---
        // Баланс жертвы обнулён без её согласия и без возможности возврата.
        assertEq(usdt.balanceOf(victim), 0, "victim funds destroyed");

        // totalSupply уменьшился ровно на конфискованную сумму.
        assertEq(usdt.totalSupply(), supplyBefore - victimBefore, "totalSupply decreased by seized amount");

        console2.log("victim balance before :", victimBefore);
        console2.log("victim balance after  :", usdt.balanceOf(victim));
        console2.log("totalSupply before    :", supplyBefore);
        console2.log("totalSupply after     :", usdt.totalSupply());
    }

    /// @notice Контрольная проверка: жертва НЕ может защититься сама.
    ///         После blacklist её собственный transfer ревертится (require(!isBlackListed[msg.sender])).
    function test_VictimCannotEscapeBlacklist() public {
        usdt.addBlackList(victim);

        // Жертва пытается спасти токены, отправив их на другой свой адрес — не выйдет.
        vm.prank(victim);
        vm.expectRevert();
        usdt.transfer(address(0xBEEF), 1 * 10 ** DECIMALS);
    }
}
