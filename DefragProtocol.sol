// SPDX-License-Identifier: BUSL-1.1

pragma solidity =0.8.4;

import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

import "./interfaces/IERC20Modified.sol";
import "./library/DefragSafeERC20.sol";

/**
 * @title Protocol Contract
 * @author Defrag [security@defrag.com]
 */
contract DefragProtocol is
    Initializable,
    OwnableUpgradeable,
    ReentrancyGuardUpgradeable
{
    using DefragSafeERC20 for IERC20Modified;

    event ToggleActivated(bool isActive);
    event UpdatedDefragToken(
        address indexed positionToken,
        bool isDefragIndexToken
    );
    event UpdatedFees(uint256 issuanceFees, uint256 redeemFees);
    event UpdatedMinimumCollateral(uint256 newMinimumCollateralQty);
    event ClaimedFees(uint256 fees);
    event ToggledVolatilityTokenPause(bool isPause);
    event Settled(uint256 settlementPrice);
    event Collateralized(
        address indexed sender,
        uint256 collateralLock,
        uint256 positionTokensMinted,
        uint256 fees
    );
    event Redeemed(
        address indexed sender,
        uint256 collateralReleased,
        uint256 DefragIndexTokenBurned,
        uint256 inverseDefragIndexTokenBurned,
        uint256 fees
    );

    // Has the value of minimum collateral qty required
    uint256 public minimumCollateralQty;

    // Has the boolean state of protocol
    bool public active;

    // Has the boolean state of protocol settlement
    bool public isSettled;

    // Defrag tokens
    IERC20Modified public DefragToken;
    IERC20Modified public inverseDefragToken;

    // Only ERC20 standard functions are used by the collateral defined here.
    // Address of the acceptable collateral token.
    IERC20Modified public collateral;

    // Used to calculate collateralize fee
    uint256 public issuanceFees;

    // Used to calculate redeem fee
    uint256 public redeemFees;

    // Total fee amount for call of collateralize and redeem
    uint256 public accumulatedFees;

    // Percentage value is upto two decimal places, so we're dividing it by 10000
    // Set the max fee as 5%, i.e. 500/10000.
    uint256 constant MAX_FEE = 500;

    // No need to add 18 decimals, because they are already considered in respective token qty arguments.
    uint256 public DefragCapRatio;

    // This is the price of Defrag index, ranges from 0 to DefragCapRatio,
    // and the inverse can be calculated by subtracting DefragCapRatio by settlementPrice.
    uint256 public settlementPrice;

    /**
     * @notice Used to check contract is active
     */
    modifier onlyActive() {
        require(active, "Defrag: Protocol not active");
        _;
    }

    /**
     * @notice Used to check contract is not settled
     */
    modifier onlyNotSettled() {
        require(!isSettled, "Defrag: Protocol settled");
        _;
    }

    /**
     * @notice Used to check contract is settled
     */
    modifier onlySettled() {
        require(isSettled, "Defrag: Protocol not settled");
        _;
    }

    /**
     * @dev Makes the protocol `active` at deployment
     * @dev Sets the `minimumCollateralQty`
     * @dev Makes the collateral token as `collateral`
     * @dev Assign position tokens
     * @dev Sets the `DefragCapRatio`
     *
     * @param _collateralTokenAddress is address of collateral token typecasted to IERC20Modified
     * @param _DefragToken is address of Defrag token typecasted to IERC20Modified
     * @param _inverseDefragToken is address of inverse Defrag index token typecasted to IERC20Modified
     * @param _minimumCollateralQty is the minimum qty of tokens need to mint 0.1 Defrag and inverse Defrag tokens
     * @param _DefragCapRatio is the cap for Defrag
     */
    function initialize(
        IERC20Modified _collateralTokenAddress,
        IERC20Modified _DefragToken,
        IERC20Modified _inverseDefragToken,
        uint256 _minimumCollateralQty,
        uint256 _DefragCapRatio
    ) external initializer {
        __Ownable_init();
        __ReentrancyGuard_init();

        require(
            _minimumCollateralQty > 0,
            "Defrag: Minimum collateral quantity should be greater than 0"
        );

        active = true;
        minimumCollateralQty = _minimumCollateralQty;
        collateral = _collateralTokenAddress;
        DefragToken = _DefragToken;
        inverseDefragToken = _inverseDefragToken;
        DefragCapRatio = _DefragCapRatio;
    }

    /**
     * @notice Toggles the active variable. Restricted to only the owner of the contract.
     */
    function toggleActive() external onlyOwner {
        active = !active;
        emit ToggleActivated(active);
    }

    /**
     * @notice Update the `minimumCollateralQty`
     * @param _newMinimumCollQty Provides the new minimum collateral quantity
     */
    function updateMinimumCollQty(uint256 _newMinimumCollQty)
        external
        onlyOwner
    {
        require(
            _newMinimumCollQty > 0,
            "Defrag: Minimum collateral quantity should be greater than 0"
        );
        minimumCollateralQty = _newMinimumCollQty;
        emit UpdatedMinimumCollateral(_newMinimumCollQty);
    }

    /**
     * @notice Update the {Defrag Token}
     * @param _positionToken Address of the new position token
     * @param _isDefragIndexToken Type of the position token, { DefragIndexToken: true, InverseDefragIndexToken: false }
     */
    function updateDefragToken(
        address _positionToken,
        bool _isDefragIndexToken
    ) external onlyOwner {
        _isDefragIndexToken
            ? DefragToken = IERC20Modified(_positionToken)
            : inverseDefragToken = IERC20Modified(_positionToken);
        emit UpdatedDefragToken(_positionToken, _isDefragIndexToken);
    }

    /**
     * @notice Add collateral to the protocol and mint the position tokens
     * @param _collateralQty Quantity of the collateral being deposited
     *
     * NOTE: Collateral quantity should be at least required minimum collateral quantity
     *
     * Calculation: Get the quantity for position token
     * Mint the position token for `msg.sender`
     *
     */
    function collateralize(uint256 _collateralQty)
        external
        onlyActive
        onlyNotSettled
    {
        require(
            _collateralQty >= minimumCollateralQty,
            "Defrag: CollateralQty > minimum qty required"
        );

        // Mechanism to calculate the collateral qty using the increase in balance
        // of protocol contract to counter USDT's fee mechanism, which can be enabled in future
        uint256 initialProtocolBalance = collateral.balanceOf(address(this));
        collateral.safeTransferFrom(msg.sender, address(this), _collateralQty);
        uint256 finalProtocolBalance = collateral.balanceOf(address(this));

        _collateralQty = finalProtocolBalance - initialProtocolBalance;

        uint256 fee;
        if (issuanceFees > 0) {
            fee = (_collateralQty * issuanceFees) / 10000;
            _collateralQty = _collateralQty - fee;
            accumulatedFees = accumulatedFees + fee;
        }

        uint256 qtyToBeMinted = _collateralQty / volatilityCapRatio;

        DefragToken.mint(msg.sender, qtyToBeMinted);
        inverseDefragToken.mint(msg.sender, qtyToBeMinted);

        emit Collateralized(msg.sender, _collateralQty, qtyToBeMinted, fee);
    }

    /**
     * @notice Redeem the collateral from the protocol by providing the position token
     *
     * @param _positionTokenQty Quantity of the position token that the user is surrendering
     *
     * Amount of collateral is `_positionTokenQty` by the DefragCapRatio.
     * Burn the position token
     *
     * Safely transfer the collateral to `msg.sender`
     */
    function redeem(uint256 _positionTokenQty)
        external
        onlyActive
        onlyNotSettled
    {
        uint256 collQtyToBeRedeemed = _positionTokenQty * DefragCapRatio;

        _redeem(collQtyToBeRedeemed, _positionTokenQty, _positionTokenQty);
    }

    /**
     * @notice Redeem the collateral from the protocol after settlement
     *
     * @param _DefragIndexTokenQty Quantity of the Defrag index token that the user is surrendering
     * @param _inverseDefragIndexTokenQty Quantity of the inverse Defrag index token that the user is surrendering
     *
     * Amount of collateral is `_DefragIndexTokenQty` by the settlementPrice and `_inverseDefragIndexTokenQty`
     * by DefragCapRatio - settlementPrice
     * Burn the position token
     *
     * Safely transfer the collateral to `msg.sender`
     */
    function redeemSettled(
        uint256 _DefragIndexTokenQty,
        uint256 _inverseDefragIndexTokenQty
    ) external onlyActive onlySettled {
        uint256 collQtyToBeRedeemed =
            (_DefragIndexTokenQty * settlementPrice) +
                (_inverseDefragIndexTokenQty *
                    (DefragCapRatio - settlementPrice));

        _redeem(
            collQtyToBeRedeemed,
            _DefragIndexTokenQty,
            _inverseDefragIndexTokenQty
        );
    }

    /**
     * @notice Settle the contract, preventing new minting and providing individual token redemption
     *
     * @param _settlementPrice The price of the volatility index after settlement
     *
     * The inverse defrag token at settlement is worth DefragCapRatio - Defrag index settlement price
     */
    function settle(uint256 _settlementPrice)
        external
        onlyOwner
        onlyNotSettled
    {
        require(
            _settlementPrice <= DefragCapRatio,
            "Defrag: _settlementPrice should be less than equal to DefragCapRatio"
        );
        settlementPrice = _settlementPrice;
        isSettled = true;
        emit Settled(settlementPrice);
    }

    /**
     * @notice Recover tokens accidentally sent to this contract
     */
    function recoverTokens(
        address _token,
        address _toWhom,
        uint256 _howMuch
    ) external nonReentrant onlyOwner {
        require(
            _token != address(collateral),
            "Defrag: Collateral token not allowed"
        );
        IERC20Modified(_token).safeTransfer(_toWhom, _howMuch);
    }

    /**
     * @notice Update the percentage of `issuanceFees` and `redeemFees`
     *
     * @param _issuanceFees Percentage of fees required to collateralize the collateral
     * @param _redeemFees Percentage of fees required to redeem the collateral
     */
    function updateFees(uint256 _issuanceFees, uint256 _redeemFees)
        external
        onlyOwner
    {
        require(
            _issuanceFees <= MAX_FEE && _redeemFees <= MAX_FEE,
            "Defrag: issue/redeem fees should be less than MAX_FEE"
        );

        issuanceFees = _issuanceFees;
        redeemFees = _redeemFees;

        emit UpdatedFees(_issuanceFees, _redeemFees);
    }

    /**
     * @notice Safely transfer the accumulated fees to owner
     */
    function claimAccumulatedFees() external onlyOwner {
        uint256 claimedAccumulatedFees = accumulatedFees;
        delete accumulatedFees;

        collateral.safeTransfer(owner(), claimedAccumulatedFees);

        emit ClaimedFees(claimedAccumulatedFees);
    }

    /**
     * @notice Pause/unpause Defrag position token.
     *
     * @param _isPause Boolean value to pause or unpause the position token { true = pause, false = unpause }
     */
    function togglePause(bool _isPause) external onlyOwner {
        if (_isPause) {
            DefragToken.pause();
            inverseDefragToken.pause();
        } else {
            DefragToken.unpause();
            inverseDefragToken.unpause();
        }

        emit ToggledDefragTokenPause(_isPause);
    }

    function _redeem(
        uint256 _collateralQtyRedeemed,
        uint256 _DefragIndexTokenQty,
        uint256 _inverseDefragIndexTokenQty
    ) internal {
        uint256 fee;
        if (redeemFees > 0) {
            fee = (_collateralQtyRedeemed * redeemFees) / 10000;
            _collateralQtyRedeemed = _collateralQtyRedeemed - fee;
            accumulatedFees = accumulatedFees + fee;
        }

        DefragToken.burn(msg.sender, _DefragIndexTokenQty);
        inverseDefragToken.burn(
            msg.sender,
            _inverseDefragIndexTokenQty
        );

        collateral.safeTransfer(msg.sender, _collateralQtyRedeemed);

        emit Redeemed(
            msg.sender,
            _collateralQtyRedeemed,
            _DefragIndexTokenQty,
            _inverseDefragIndexTokenQty,
            fee
        );
    }
}
