// SPDX-License-Identifier: BUSL-1.1

pragma solidity =0.8.4;

import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts/proxy/Clones.sol";

import "./interfaces/IERC20Modified.sol";
import "./tokens/DefragPositionToken.sol";
import "./DefragProtocol.sol";

/**
 * Factory is used to register respective index and clone position tokens
 */
contract DefragIndexFactory is OwnableUpgradeable {
    event IndexRegistered(
        uint256 indexed indexCount,
        DefragProtocol indexed index
    );

    event VolatilityTokenCreated(
        IERC20Modified indexed DefragToken,
        IERC20Modified indexed inverseDefragToken,
        string tokenName,
        string tokenSymbol
    );

    // Defrag token implementation contract for factory
    address public positionTokenImplementation;

    // To store the address of Defrag.
    mapping(uint256 => address) public getIndex;

    // To store the name of Defrag
    mapping(uint256 => string) public getIndexSymbol;

    // Used to store the address and name of defragf at a particular _index (incremental state of 1)
    uint256 public indexCount;

    // These are position token roles
    // Calculated as keccak256("DEFRAG_PROTOCOL_ROLE").
    bytes32 private constant DEFRAG_PROTOCOL_ROLE =
        0x33ba6006595f7ad5c59211bde33456cab351f47602fc04f644c8690bc73c4e16;

    // Referenced from Openzepplin AccessControl.sol
    bytes32 private constant DEFAULT_ADMIN_ROLE = 0x00;

    /**
     * @notice Get the address of implementation contracts instance.
     */
    function initialize(address _implementation) external initializer {
        __Ownable_init();

        positionTokenImplementation = _implementation;
    }

    /**
     * @notice Get the counterfactual address of position token implementation
     */
    function determineDefragTokenAddress(
        uint256 _indexCount,
        string memory _name,
        string memory _symbol
    ) external view returns (address) {
        bytes32 salt = keccak256(abi.encodePacked(_indexCount, _name, _symbol));
        return
            Clones.predictDeterministicAddress(
                positionTokenImplementation,
                salt,
                address(this)
            );
    }

    /**
     * @notice Clones new Defrag tokens - { returns Defrag tokens address typecasted to IERC20Modified }
     *
     * @dev Increment the indexCount by 1
     * @dev Check if state is at NotInitialized
     * @dev Clones the Defrag and inverse volatility tokens
     * @dev Stores the Defrag name, referenced by indexCount
     * @dev Emits event of Defrag token name & symbol, indexCount(position), position tokens address
     *
     * @param _tokenName is the name for Defrag
     * @param _tokenSymbol is the symbol for Defrag
     */
    function createDefragTokens(
        string memory _tokenName,
        string memory _tokenSymbol
    )
        external
        onlyOwner
        returns (
            IERC20Modified Token,
            IERC20Modified inverseDefragToken
        )
    {
        DefragToken = IERC20Modified(
            _clonePositonToken(_tokenName, _tokenSymbol)
        );
        inverseDefragToken = IERC20Modified(
            _clonePositonToken(
                string(abi.encodePacked("Inverse ", _tokenName)),
                string(abi.encodePacked("i", _tokenSymbol))
            )
        );

        emit DefragTokenCreated(
            DefragToken,
            inverseDefragToken,
            _tokenName,
            _tokenSymbol
        );
    }

    /**
     * @notice Registers the Defrag Protocol
     *
     * @dev Check if state is at DefragCreated
     * @dev Stores index address, referenced by indexCount
     * @dev Grants the DEFRAG_PROTOCOL_ROLE and DEFAULT_ADMIN_ROLE to protocol
     * @dev Update index state to Completed
     * @dev Emit event of index registered with indexCount and index address
     *
     * @param _volmexProtocolContract Address of DefragProtocol typecasted to DefragProtocol
     * @param _collateralSymbol Symbol of collateral used
     */
    function registerIndex(
        DefragProtocol _DefragProtocolContract,
        string memory _collateralSymbol
    ) external onlyOwner {
        indexCount++;

        getIndex[indexCount] = address(_DefragProtocolContract);

        IERC20Modified DefragToken =
            _DefragProtocolContract.DefragToken();
        IERC20Modified inverseDefragToken =
            _DefragProtocolContract.inverseDefragToken();

        getIndexSymbol[indexCount] = string(
            abi.encodePacked(DefragToken.symbol(), _collateralSymbol)
        );

        volatilityToken.grantRole(
            DEFRAG_PROTOCOL_ROLE,
            address(_volmexProtocolContract)
        );

        inverseVolatilityToken.grantRole(
            DEFRAG_PROTOCOL_ROLE,
            address(_DefragProtocolContract)
        );

        DefragToken.grantRole(DEFAULT_ADMIN_ROLE, msg.sender);

        inverseDefragToken.grantRole(DEFAULT_ADMIN_ROLE, msg.sender);

        emit IndexRegistered(indexCount, _DefragProtocolContract);
    }

    /**
     * @notice Clones the position token - { returns position token address }
     *
     * @dev Generates a salt using indexCount, token name and token symbol
     * @dev Clone the position token implementation with a salt make it deterministic
     * @dev Initializes the position token
     *
     * @param _name is the name of volatility token
     * @param _symbol is the symbol of volatility token
     */
    function _clonePositonToken(string memory _name, string memory _symbol)
        private
        returns (address)
    {
        bytes32 salt = keccak256(abi.encodePacked(indexCount, _name, _symbol));

        VolmexPositionToken newVolatilityToken =
            VolmexPositionToken(
                Clones.cloneDeterministic(positionTokenImplementation, salt)
            );
        newVolatilityToken.initialize(_name, _symbol);

        return address(newVolatilityToken);
    }
}
