// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

/// @title WETH9Vulnerable — копия WETH9, уязвимая к reentrancy
/// @notice В функции withdraw порядок операций нарушен: сначала внешний вызов
///         (перевод эфира), а уменьшение баланса происходит только после него.
///         Это нарушает паттерн Checks-Effects-Interactions и позволяет
///         повторно войти в withdraw до обновления баланса.
contract WETH9Vulnerable {
    string public name = "Wrapped Ether Vulnerable";
    string public symbol = "WETH";
    uint8 public decimals = 18;

    event Deposit(address indexed dst, uint256 wad);
    event Withdrawal(address indexed src, uint256 wad);
    event Transfer(address indexed src, address indexed dst, uint256 wad);
    event Approval(address indexed src, address indexed guy, uint256 wad);

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    /// @notice Позволяет отправлять эфир напрямую на контракт — сработает deposit
    receive() external payable {
        deposit();
    }

    /// @notice Оборачивает эфир: увеличивает баланс отправителя на msg.value
    function deposit() public payable {
        balanceOf[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    /// @notice Уязвимый вывод средств.
    /// @dev УЯЗВИМОСТЬ: сначала выполняется внешний вызов (перевод эфира),
    ///      и только потом уменьшается баланс. Пока баланс не обновлён,
    ///      атакующий в своём receive() может рекурсивно снова вызвать withdraw.
    function withdraw(uint256 wad) public {
        // Проверка (Check) — баланса достаточно
        require(balanceOf[msg.sender] >= wad, "WETH9Vulnerable: insufficient balance");

        // Взаимодействие (Interaction) ИДЁТ РАНЬШЕ изменения состояния — это и есть баг
        (bool success, ) = msg.sender.call{value: wad}("");
        require(success, "WETH9Vulnerable: ETH transfer failed");

        // Изменение состояния (Effect) происходит слишком поздно.
        // ВАЖНО: в Solidity 0.8.x арифметика проверяемая, поэтому при "разматывании"
        // рекурсии второй вызов `-= wad` ушёл бы в underflow и откатил всю атаку —
        // встроенная проверка переполнения случайно защищает от наивного слива.
        // Чтобы воспроизвести классический reentrancy (как в старых версиях Solidity
        // с оборачиванием), намеренно отключаем проверку через unchecked.
        unchecked {
            balanceOf[msg.sender] -= wad;
        }

        emit Withdrawal(msg.sender, wad);
    }

    /// @notice Общее предложение = баланс эфира на контракте
    function totalSupply() public view returns (uint256) {
        return address(this).balance;
    }

    function approve(address guy, uint256 wad) public returns (bool) {
        allowance[msg.sender][guy] = wad;
        emit Approval(msg.sender, guy, wad);
        return true;
    }

    function transfer(address dst, uint256 wad) public returns (bool) {
        return transferFrom(msg.sender, dst, wad);
    }

    function transferFrom(address src, address dst, uint256 wad) public returns (bool) {
        require(balanceOf[src] >= wad, "WETH9Vulnerable: insufficient balance");

        if (src != msg.sender && allowance[src][msg.sender] != type(uint256).max) {
            require(allowance[src][msg.sender] >= wad, "WETH9Vulnerable: insufficient allowance");
            allowance[src][msg.sender] -= wad;
        }

        balanceOf[src] -= wad;
        balanceOf[dst] += wad;

        emit Transfer(src, dst, wad);
        return true;
    }
}
