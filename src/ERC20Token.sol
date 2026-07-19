// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title ERC20Token
 * @dev Implementation of the ERC20 interface with customizable token properties.
 * This contract extends the ERC20 standard with the ability for the contract owner to
 * modify token name, symbol, and decimals after deployment. It also includes minting
 * and burning functionalities controlled by the contract owner.
 */
contract ERC20Token is ERC20, Ownable {
    uint8 private _decimals;
    string private _name;
    string private _symbol;
    bool private _isDecimalsSet;

    uint256 constant internal MAX_DECIMALS = 77; // log10(2^256 - 1)

    /**
     * @dev emitted when the decimals are changed by the owner.
     */
    event SetDecimals(uint8 precision);

    /**
     * @dev emitted when the name is changed by the owner.
     */
    event SetName(string name);

    /**
     * @dev emitted when the symbol is changed by the owner.
     */
    event SetSymbol(string symbol);

    /**
     * @dev Constructor for initializing the ERC20Token contract Sets the owner of the contract
     *      to the deployer of the contract. Mints the initial supply of tokens to the deployer.
     *
     *      Reverts if the number of decimal places is greater than `MAX_DECIMALS`.
     * @param initialName The name of the token.
     * @param initialSymbol The symbol of the token.
     * @param initSupply The initial supply of tokens to mint upon contract deployment.
     * @param initialDecimals The number of decimal places for the token.
     */
    constructor(string memory initialName, string memory initialSymbol, uint256 initSupply, uint8 initialDecimals)
    ERC20(initialName, initialSymbol)
    Ownable(_msgSender())
    {
        _mint(_msgSender(), initSupply);
        _decimals = initialDecimals;
        _name = initialName;
        _symbol = initialSymbol;
        _isDecimalsSet = false;
        require(initialDecimals <= MAX_DECIMALS, "ERC20Token: precision too high");
    }

    /**
     * @notice Mint new tokens.
     * @dev Mint new tokens to the specified account. Only the owner can call this function.
     *      A `Transfer` event is emitted from the internal `_mint` function.
     * @param account The account to mint the tokens to.
     * @param amount The amount of tokens to mint.
     */
    function mint(address account, uint256 amount) external onlyOwner {
        _mint(account, amount);
    }

    /**
     * @notice Burn tokens.
     * @dev Burn tokens from the specified account. Only the owner can call this function.
     *      A `Transfer` event is emitted from the internal `_burn` function.
     * @param account The account to burn the tokens from.
     * @param amount The amount of tokens to burn.
     */
    function burn(address account, uint256 amount) external onlyOwner {
        _burn(account, amount);
    }

    /**
     * @notice Set the number of decimal places for the token.
     * @dev Set the number of decimal places for the token. Only the owner can call this function.
     *
     * Reverts if one of the following is true:
     *   - the number of decimal places is already set.
     *   - the new number of decimal places is greater than `MAX_DECIMALS`.
     * @param newDecimals The number of decimal places for the token.
     */
    function setDecimals(uint8 newDecimals) external onlyOwner {
        require(!_isDecimalsSet, "ERC20Token: decimals is already set");
        require(newDecimals <= MAX_DECIMALS, "ERC20Token: precision too high");
        _decimals = newDecimals;
        _isDecimalsSet = true;
        emit SetDecimals(newDecimals);
    }

    /**
     * @notice Set the name of the token.
     * @dev Set the name of the token. Only the owner can call this function.
     * @param newName The name of the token.
     */
    function setName(string memory newName) external onlyOwner {
        _name = newName;
        emit SetName(newName);
    }

    /**
     * @notice Set the symbol of the token.
     * @dev Set the symbol of the token. Only the owner can call this function.
     * @param newSymbol The symbol of the token.
     */
    function setSymbol(string memory newSymbol) external onlyOwner {
        _symbol = newSymbol;
        emit SetSymbol(newSymbol);
    }

    /**
     * @notice Get the number of decimal places for the token.
     * @return The number of decimal places for the token.
     */
    function decimals() public view virtual override returns (uint8) {
        return _decimals;
    }

    /**
     * @notice Get the name of the token.
     * @return The name of the token.
     */
    function name() public view virtual override returns (string memory) {
        return _name;
    }

    /**
     * @notice Get the symbol of the token.
     * @return The symbol of the token.
     */
    function symbol() public view virtual override returns (string memory) {
        return _symbol;
    }
}
