// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.8.2) (token/ERC721/ERC721.sol)

pragma solidity ^0.8.0;

import '@openzeppelin/contracts/token/ERC721/IERC721.sol';
import '@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol';
import '@openzeppelin/contracts/token/ERC721/extensions/IERC721Metadata.sol';
import '@openzeppelin/contracts/utils/Address.sol';
import '@openzeppelin/contracts/utils/Context.sol';
import '@openzeppelin/contracts/utils/Strings.sol';
import '@openzeppelin/contracts/utils/introspection/ERC165.sol';

import "@openzeppelin/contracts/access/AccessControl.sol";


//import "@openzeppelin/openzeppelin-contracts/blob/v2.5.1/contracts/access/roles/WhitelistAdminRole.sol"

/**
 * @dev Implementation of https://eips.ethereum.org/EIPS/eip-721[ERC721] Non-Fungible Token Standard
 */

contract ERC721ExclusiveRights is Context, ERC165, IERC721, IERC721Metadata, AccessControl {


    using Address for address;
    using Strings for uint256;
    string private _name;
    string private _symbol;
    
    struct AddressData {
        uint256 balance;
        bool allowList;
    }

    mapping(address => AddressData) internal _addressData;


    mapping(uint256 => address) private _owners;


    mapping(address => uint256) private _balances;


    mapping(address => bool) public allowList;


    mapping(uint256 => address) private _tokenApprovals;


    mapping(address => mapping(address => bool)) private _operatorApprovals;

    bytes32 public constant ADMIN_ROLE = keccak256(bytes("ADMIN_ROLE"));
    bytes32 public constant BURNER_ROLE = keccak256(bytes("BURNER_ROLE"));
    bytes32 public constant WHITE_LIST_ADMIN_ROLE = keccak256(bytes("WHITE_LIST_ADMIN_ROLE"));
    

    bool public publicMintOpen = false;
    bool public whiteListMintOpen = false;

    constructor(string memory name_, string memory symbol_) {
        _name = name_;
        _symbol = symbol_;
        grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _setRoleAdmin(BURNER_ROLE, ADMIN_ROLE);
        _setRoleAdmin(WHITE_LIST_ADMIN_ROLE, ADMIN_ROLE);
    }
    
    function _addToWhitelist(address[] calldata addresses) internal onlyRole(WHITE_LIST_ADMIN_ROLE) {
        for(uint256 i = 0; i < addresses.length; i++){
            _addressData[addresses[i]].allowList = true;
        }
    }
    function _removeFromWhitelistArray(address[] calldata addresses) internal onlyRole(WHITE_LIST_ADMIN_ROLE) {
        for(uint256 i = 0; i < addresses.length; i++){
            delete _addressData[addresses[i]].allowList;
        }
    }
    function verifyAddress(address owner) public view returns (bool) {
        return _addressData[owner].allowList;
    }

    function _setWhiteList(address owner) internal onlyRole(WHITE_LIST_ADMIN_ROLE) {
        _addressData[owner].allowList = true;
    }

    function _removeFromWhitelist(address owner) internal onlyRole(WHITE_LIST_ADMIN_ROLE) {
            delete _addressData[owner].allowList;
    }    
    
    function name() public view virtual override returns (string memory) {
        return _name;
    }
    function symbol() public view virtual override returns (string memory) {
        return _symbol;
    }
    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165, IERC165, AccessControl) returns (bool) {
        return
            interfaceId == type(IERC721).interfaceId ||
            interfaceId == type(IERC721Metadata).interfaceId ||
            interfaceId == type(AccessControl).interfaceId ||
            super.supportsInterface(interfaceId);
    }
    function balanceOf(address owner) public view virtual override returns (uint256) {
        require(owner != address(0), "ERC721: address zero is not a valid owner");
        return _addressData[owner].balance;
    }
    function ownerOf(uint256 tokenId) public view virtual override returns (address) {
        address owner = _ownerOf(tokenId);
        require(owner != address(0), "ERC721: invalid token ID");
        return owner;
    }
    function _ownerOf(uint256 tokenId) internal view virtual returns (address) {
        return _owners[tokenId];
    }
    function tokenURI(uint256 tokenId) public view virtual override returns (string memory) {
        _requireMinted(tokenId);
        string memory baseURI = _baseURI();
        return bytes(baseURI).length > 0 ? string(abi.encodePacked(baseURI, tokenId.toString())) : "";
    }
    function _baseURI() internal view virtual returns (string memory) {
        return "";
    }
    function _exists(uint256 tokenId) internal view virtual returns (bool) {
        return _ownerOf(tokenId) != address(0);
    }
    function _requireMinted(uint256 tokenId) internal view virtual {
        require(_exists(tokenId), "ERC721: invalid token ID");
    }  
    function getApproved(uint256 tokenId) public view virtual override onlyRole(WHITE_LIST_ADMIN_ROLE) returns (address)  {
        _requireMinted(tokenId);
        return _tokenApprovals[tokenId];
    }
    function approve(address to, uint256 tokenId) public virtual override {
        address owner = ERC721ExclusiveRights.ownerOf(tokenId);
        require(to != owner, "ERC721: approval to current owner");
        require(
            _msgSender() == owner || isApprovedForAll(owner, _msgSender()),
            "ERC721: approve caller is not token owner or approved for all"
        );
        _approve(to, tokenId);
    }

    function _approve(address to, uint256 tokenId) internal virtual {
        require(_addressData[to].allowList, "ERC721ER: Receiver is not on the allow list");
        _tokenApprovals[tokenId] = to;
        emit Approval(ERC721ExclusiveRights.ownerOf(tokenId), to, tokenId);
    }

    function _setApprovalForAll(address owner, address operator, bool approved) internal virtual{                                //onlyRole(WHITE_LIST_ADMIN_ROLE) {
        require(owner != operator, "ERC721ER: approve to caller");
        require(_addressData[owner].allowList, "ERC721ER: Receiver is not on the allow list");
        require(_addressData[operator].allowList, "ERC721ER: Caller is not on the allow list");
        _operatorApprovals[owner][operator] = approved;
        emit ApprovalForAll(owner, operator, approved);
    }
   
    function setApprovalForAll(address operator, bool approved) public virtual override {
        _setApprovalForAll(_msgSender(), operator, approved);
    }
 
    function isApprovedForAll(address owner, address operator) public view virtual override returns (bool) {
        return _operatorApprovals[owner][operator];
    }

    function _isApprovedOrOwner(address spender, uint256 tokenId) internal view virtual returns (bool) {
        address owner = ERC721ExclusiveRights.ownerOf(tokenId);
        return (spender == owner || isApprovedForAll(owner, spender) || getApproved(tokenId) == spender);
    }

    function transferFrom(address from, address to, uint256 tokenId) public virtual override {
        require(_isApprovedOrOwner(_msgSender(), tokenId), "ERC721ER: caller is not token owner or approved");
        _transfer(from, to, tokenId);
    }
    function safeTransferFrom(address from, address to, uint256 tokenId) public virtual override {
        safeTransferFrom(from, to, tokenId, "");
    }
    function safeTransferFrom(address from, address to, uint256 tokenId, bytes memory data) public virtual override {
        require(_isApprovedOrOwner(_msgSender(), tokenId), "ERC721ER: caller is not token owner or approved");
        _safeTransfer(from, to, tokenId, data);
    }
    function _safeTransfer(address from, address to, uint256 tokenId, bytes memory data) internal virtual {
        _transfer(from, to, tokenId);
        require(_checkOnERC721Received(from, to, tokenId, data), "ERC721ER: transfer to non ERC721Receiver implementer");
    }

    function _editMintWindows(bool _publicMintOpen, bool _whiteListMintOpen) internal onlyRole(DEFAULT_ADMIN_ROLE) {
        publicMintOpen = _publicMintOpen;
        whiteListMintOpen = _whiteListMintOpen;
    }

    function _safeMint(address to, uint256 tokenId) internal virtual {
        _safeMint(to, tokenId, "");
    }
    function _safeMint(address to, uint256 tokenId, bytes memory data) internal virtual {
        _mint(to, tokenId);
        require(
            _checkOnERC721Received(address(0), to, tokenId, data),
            "ERC721: transfer to non ERC721Receiver implementer"
        );
    }

    error WhitelistMintClosed();
    error PublicMintClosed();

    function _mint(address to, uint256 tokenId) internal virtual {
        require(to != address(0), "ERC721ER: mint to the zero address");
        require(!_exists(tokenId), "ERC721ER: token already minted");
        if (whiteListMintOpen) {
            require(_addressData[to].allowList, "ERC721ER: Receiver is not on the allow list");
            require(_addressData[_msgSender()].allowList, "ERC721ER: Caller is not on the allow list");
            _beforeTokenTransfer(address(0), to, tokenId, 1);
            require(!_exists(tokenId), "ERC721ER: token already minted");
            unchecked { _addressData[to].balance += 1; }
            _owners[tokenId] = to;
            emit Transfer(address(0), to, tokenId);
            _afterTokenTransfer(address(0), to, tokenId, 1);
        revert WhitelistMintClosed(); }
        if (publicMintOpen) {
            _beforeTokenTransfer(address(0), to, tokenId, 1);
            require(!_exists(tokenId), "ERC721ER: token already minted");
            unchecked { _addressData[to].balance += 1; }
            _owners[tokenId] = to;
            emit Transfer(address(0), to, tokenId);
            _afterTokenTransfer(address(0), to, tokenId, 1);
        revert PublicMintClosed();}
    }

    function _burn(uint256 tokenId) internal virtual onlyRole(BURNER_ROLE) {
        address owner = ERC721ExclusiveRights.ownerOf(tokenId);
        _beforeTokenTransfer(owner, address(0), tokenId, 1);
        owner = ERC721ExclusiveRights.ownerOf(tokenId);
        delete _tokenApprovals[tokenId];
        unchecked {_addressData[owner].balance -= 1; }
        delete _owners[tokenId];
        emit Transfer(owner, address(0), tokenId);
        _afterTokenTransfer(owner, address(0), tokenId, 1);
    }

    function _transfer(address from, address to, uint256 tokenId) internal virtual {
        require(ERC721ExclusiveRights.ownerOf(tokenId) == from, "ERC721ER: transfer from incorrect owner");
        require(to != address(0), "ERC721ER: transfer to the zero address");
        require(_addressData[to].allowList, "ERC721ER: Receiver is not on the allow list");
        
        _beforeTokenTransfer(from, to, tokenId, 1);
        // Check that tokenId was not transferred by `_beforeTokenTransfer` hook
        require(ERC721ExclusiveRights.ownerOf(tokenId) == from, "ERC721ER: transfer from incorrect owner");
        // Clear approvals from the previous owner
        delete _tokenApprovals[tokenId];

        unchecked {
            _addressData[from].balance -= 1;
            _addressData[to].balance += 1;
        }

        if (_addressData[from].balance == 0) {_removeFromWhitelist(from);}
        _owners[tokenId] = to;
        emit Transfer(from, to, tokenId);
        _afterTokenTransfer(from, to, tokenId, 1);
    }

    function _checkOnERC721Received(address from, address to, uint256 tokenId, bytes memory data) private returns (bool) {
        if (to.isContract()) {
            try IERC721Receiver(to).onERC721Received(_msgSender(), from, tokenId, data) returns (bytes4 retval) {
                return retval == IERC721Receiver.onERC721Received.selector;
            } catch (bytes memory reason) {
                if (reason.length == 0) {
                    revert("ERC721: transfer to non ERC721Receiver implementer");
                } else {
                    assembly {
                        revert(add(32, reason), mload(reason))
                    }
                }
            }
        } else {
            return true;
        }
    }
    function _beforeTokenTransfer(address from, address to, uint256 firstTokenId, uint256 batchSize) internal virtual {}
    function _afterTokenTransfer(address from, address to, uint256 firstTokenId, uint256 batchSize) internal virtual {}
    function __unsafe_increaseBalance(address account, uint256 amount) internal { _addressData[account].balance += amount; }
}
