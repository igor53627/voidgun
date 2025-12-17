// SPDX-License-Identifier: MIT
pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/VoidgunPool.sol";
import "../src/IVerifier.sol";

contract MockVerifier is IVerifier {
    bool public shouldPass = true;
    
    function setResult(bool _pass) external {
        shouldPass = _pass;
    }
    
    function verify(bytes calldata, bytes32[] calldata) external view returns (bool) {
        return shouldPass;
    }
}

contract MockERC20 {
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    
    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }
    
    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }
    
    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(allowance[from][msg.sender] >= amount, "Insufficient allowance");
        require(balanceOf[from] >= amount, "Insufficient balance");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }
    
    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }
}

contract VoidgunPoolTest is Test {
    VoidgunPool public pool;
    MockVerifier public verifier;
    address public poseidon2;
    MockERC20 public token;
    
    address public alice = address(0xA11CE);
    address public bob = address(0xB0B);
    
    function setUp() public {
        bytes memory bytecode = vm.getCode("Poseidon2.sol:Poseidon2Yul");
        address deployed;
        assembly {
            deployed := create(0, add(bytecode, 0x20), mload(bytecode))
        }
        require(deployed != address(0), "Poseidon2Yul deployment failed");
        poseidon2 = deployed;
        
        verifier = new MockVerifier();
        pool = new VoidgunPool(address(verifier), poseidon2);
        token = new MockERC20();
        
        vm.deal(alice, 100 ether);
        token.mint(alice, 1000 ether);
    }
    
    // Helper to convert uint256 array to bytes32 array
    function toBytes32Array(uint256[] memory arr) internal pure returns (bytes32[] memory) {
        bytes32[] memory result = new bytes32[](arr.length);
        for (uint256 i = 0; i < arr.length; i++) {
            result[i] = bytes32(arr[i]);
        }
        return result;
    }
    
    // ============================================
    // Constructor Tests
    // ============================================
    
    function test_Constructor() public view {
        assertEq(address(pool.verifier()), address(verifier));
        assertEq(pool.poseidon2(), poseidon2);
        assertEq(pool.poolId(), uint256(uint160(address(pool))));
        assertEq(pool.nextIndex(), 0);
        assertTrue(pool.isKnownRoot(pool.currentRoot()));
    }
    
    function test_RevertInvalidVerifierAddress() public {
        vm.expectRevert(VoidgunPool.InvalidVerifierAddress.selector);
        new VoidgunPool(address(0), poseidon2);
    }
    
    function test_RevertInvalidPoseidon2Address() public {
        vm.expectRevert(VoidgunPool.InvalidPoseidon2Address.selector);
        new VoidgunPool(address(verifier), address(0));
    }
    
    // ============================================
    // Deposit Tests
    // ============================================
    
    function test_DepositETH() public {
        uint256 commitment = 12345;
        uint256 value = 1 ether;
        bytes memory ciphertext = hex"deadbeef";
        
        vm.prank(alice);
        pool.deposit{value: value}(commitment, value, address(0), ciphertext);
        
        assertEq(pool.nextIndex(), 1);
        assertTrue(pool.isKnownRoot(pool.currentRoot()));
    }
    
    function test_DepositETH_EmitsEvent() public {
        uint256 commitment = 12345;
        uint256 value = 1 ether;
        bytes memory ciphertext = hex"deadbeef";
        
        vm.expectEmit(true, true, false, false);
        emit VoidgunPool.Deposit(commitment, value, address(0), ciphertext, 0, 0);
        
        vm.prank(alice);
        pool.deposit{value: value}(commitment, value, address(0), ciphertext);
    }
    
    function test_DepositERC20() public {
        uint256 commitment = 12345;
        uint256 value = 100 ether;
        bytes memory ciphertext = hex"deadbeef";
        
        vm.startPrank(alice);
        token.approve(address(pool), value);
        pool.deposit(commitment, value, address(token), ciphertext);
        vm.stopPrank();
        
        assertEq(pool.nextIndex(), 1);
        assertEq(token.balanceOf(address(pool)), value);
    }
    
    function test_RevertZeroValueDeposit() public {
        vm.expectRevert(VoidgunPool.ZeroValueDeposit.selector);
        pool.deposit(12345, 0, address(0), hex"");
    }
    
    function test_RevertIncorrectETHValue() public {
        vm.expectRevert(VoidgunPool.IncorrectETHValue.selector);
        vm.prank(alice);
        pool.deposit{value: 1 ether}(12345, 2 ether, address(0), hex"");
    }
    
    function test_RevertETHNotAllowedForERC20() public {
        vm.expectRevert(VoidgunPool.ETHNotAllowedForERC20.selector);
        vm.prank(alice);
        pool.deposit{value: 1 ether}(12345, 1 ether, address(token), hex"");
    }
    
    // ============================================
    // Merkle Tree Tests
    // ============================================
    
    function test_MerkleTreeInsertion() public {
        uint256 initialRoot = pool.currentRoot();
        
        vm.prank(alice);
        pool.deposit{value: 1 ether}(111, 1 ether, address(0), hex"");
        
        uint256 newRoot = pool.currentRoot();
        assertTrue(newRoot != initialRoot, "Root should change after deposit");
        assertTrue(pool.isKnownRoot(newRoot), "New root should be known");
    }
    
    function test_MultipleDeposits() public {
        for (uint256 i = 0; i < 10; i++) {
            vm.prank(alice);
            pool.deposit{value: 0.1 ether}(i + 1, 0.1 ether, address(0), hex"");
        }
        
        assertEq(pool.nextIndex(), 10);
    }
    
    function test_HasCapacity() public view {
        assertTrue(pool.hasCapacity());
    }
    
    function test_GetLeafCount() public {
        assertEq(pool.getLeafCount(), 0);
        
        vm.prank(alice);
        pool.deposit{value: 1 ether}(111, 1 ether, address(0), hex"");
        
        assertEq(pool.getLeafCount(), 1);
    }
    
    // ============================================
    // Root History Tests
    // ============================================
    
    function test_RootHistoryPruning() public {
        // First deposit creates root #1
        vm.prank(alice);
        pool.deposit{value: 0.01 ether}(1, 0.01 ether, address(0), hex"");
        uint256 firstDepositRoot = pool.currentRoot();
        assertTrue(pool.isKnownRoot(firstDepositRoot), "First deposit root should be known");
        
        // Do 100 more deposits (101 total roots in buffer, first should be evicted)
        for (uint256 i = 2; i <= 101; i++) {
            vm.prank(alice);
            pool.deposit{value: 0.01 ether}(i, 0.01 ether, address(0), hex"");
        }
        
        assertFalse(pool.isKnownRoot(firstDepositRoot), "First deposit root should be pruned after 100 more inserts");
    }
    
    // ============================================
    // Shielded Transfer Tests
    // ============================================
    
    function test_ShieldedTransfer() public {
        vm.prank(alice);
        pool.deposit{value: 1 ether}(111, 1 ether, address(0), hex"");
        
        uint256 root = pool.currentRoot();
        uint256[] memory publicInputsU = new uint256[](9);
        publicInputsU[0] = root;
        publicInputsU[1] = 222; // cmOut
        publicInputsU[2] = 333; // cmChange
        publicInputsU[3] = 444; // nfNote
        publicInputsU[4] = 555; // nfTx
        publicInputsU[5] = 0;   // gasTip
        publicInputsU[6] = 0;   // gasFeeCap
        publicInputsU[7] = 0;   // tokenType (ETH)
        publicInputsU[8] = pool.poolId(); // poolId
        
        pool.shieldedTransfer(toBytes32Array(publicInputsU), hex"00", hex"00", hex"00");
        
        assertTrue(pool.nullifiedNotes(444));
        assertTrue(pool.nullifiedTxs(555));
        assertEq(pool.nextIndex(), 3); // 1 deposit + 2 outputs
    }
    
    function test_RevertInvalidPoolId() public {
        vm.prank(alice);
        pool.deposit{value: 1 ether}(111, 1 ether, address(0), hex"");
        
        uint256[] memory publicInputsU = new uint256[](9);
        publicInputsU[0] = pool.currentRoot();
        publicInputsU[8] = 999; // wrong poolId
        
        vm.expectRevert(VoidgunPool.InvalidPoolId.selector);
        pool.shieldedTransfer(toBytes32Array(publicInputsU), hex"00", hex"", hex"");
    }
    
    function test_RevertUnknownRoot() public {
        uint256[] memory publicInputsU = new uint256[](9);
        publicInputsU[0] = 12345; // unknown root
        publicInputsU[8] = pool.poolId();
        
        vm.expectRevert(VoidgunPool.UnknownRoot.selector);
        pool.shieldedTransfer(toBytes32Array(publicInputsU), hex"00", hex"", hex"");
    }
    
    function test_RevertNoteAlreadySpent() public {
        vm.prank(alice);
        pool.deposit{value: 1 ether}(111, 1 ether, address(0), hex"");
        
        uint256[] memory publicInputsU = new uint256[](9);
        publicInputsU[0] = pool.currentRoot();
        publicInputsU[3] = 444; // nfNote
        publicInputsU[4] = 555; // nfTx
        publicInputsU[8] = pool.poolId();
        
        pool.shieldedTransfer(toBytes32Array(publicInputsU), hex"00", hex"", hex"");
        
        publicInputsU[0] = pool.currentRoot();
        publicInputsU[4] = 666; // different nfTx
        
        vm.expectRevert(VoidgunPool.NoteAlreadySpent.selector);
        pool.shieldedTransfer(toBytes32Array(publicInputsU), hex"00", hex"", hex"");
    }
    
    function test_RevertInvalidProof() public {
        vm.prank(alice);
        pool.deposit{value: 1 ether}(111, 1 ether, address(0), hex"");
        
        verifier.setResult(false);
        
        uint256[] memory publicInputsU = new uint256[](9);
        publicInputsU[0] = pool.currentRoot();
        publicInputsU[8] = pool.poolId();
        
        vm.expectRevert(VoidgunPool.InvalidProof.selector);
        pool.shieldedTransfer(toBytes32Array(publicInputsU), hex"00", hex"", hex"");
    }
    
    function test_RevertTransactionAlreadyUsed() public {
        vm.prank(alice);
        pool.deposit{value: 1 ether}(111, 1 ether, address(0), hex"");
        
        uint256[] memory publicInputsU = new uint256[](9);
        publicInputsU[0] = pool.currentRoot();
        publicInputsU[3] = 444; // nfNote
        publicInputsU[4] = 555; // nfTx
        publicInputsU[8] = pool.poolId();
        
        pool.shieldedTransfer(toBytes32Array(publicInputsU), hex"00", hex"", hex"");
        
        publicInputsU[0] = pool.currentRoot();
        publicInputsU[3] = 666; // different nfNote
        // same nfTx = 555
        
        vm.expectRevert(VoidgunPool.TransactionAlreadyUsed.selector);
        pool.shieldedTransfer(toBytes32Array(publicInputsU), hex"00", hex"", hex"");
    }
    
    // ============================================
    // Withdraw Tests
    // ============================================
    
    function test_WithdrawETH() public {
        vm.prank(alice);
        pool.deposit{value: 1 ether}(111, 1 ether, address(0), hex"");
        
        uint256 bobBalanceBefore = bob.balance;
        
        uint256[] memory publicInputsU = new uint256[](7);
        publicInputsU[0] = pool.currentRoot();
        publicInputsU[1] = 444; // nfNote
        publicInputsU[2] = 555; // nfTx
        publicInputsU[3] = 1 ether; // value
        publicInputsU[4] = 0;   // tokenType (ETH)
        publicInputsU[5] = uint256(uint160(bob)); // recipient
        publicInputsU[6] = pool.poolId();
        
        pool.withdraw(toBytes32Array(publicInputsU), hex"00", bob, address(0), 1 ether);
        
        assertEq(bob.balance, bobBalanceBefore + 1 ether);
        assertTrue(pool.nullifiedNotes(444));
    }
    
    function test_WithdrawERC20() public {
        vm.startPrank(alice);
        token.approve(address(pool), 100 ether);
        pool.deposit(111, 100 ether, address(token), hex"");
        vm.stopPrank();
        
        uint256[] memory publicInputsU = new uint256[](7);
        publicInputsU[0] = pool.currentRoot();
        publicInputsU[1] = 444;
        publicInputsU[2] = 555;
        publicInputsU[3] = 50 ether;
        publicInputsU[4] = uint256(uint160(address(token)));
        publicInputsU[5] = uint256(uint160(bob)); // recipient
        publicInputsU[6] = pool.poolId();
        
        pool.withdraw(toBytes32Array(publicInputsU), hex"00", bob, address(token), 50 ether);
        
        assertEq(token.balanceOf(bob), 50 ether);
    }
    
    function test_RevertValueMismatch() public {
        vm.prank(alice);
        pool.deposit{value: 1 ether}(111, 1 ether, address(0), hex"");
        
        uint256[] memory publicInputsU = new uint256[](7);
        publicInputsU[0] = pool.currentRoot();
        publicInputsU[3] = 1 ether; // proof says 1 ether
        publicInputsU[5] = uint256(uint160(bob));
        publicInputsU[6] = pool.poolId();
        
        vm.expectRevert(VoidgunPool.ValueMismatch.selector);
        pool.withdraw(toBytes32Array(publicInputsU), hex"00", bob, address(0), 2 ether); // but trying to withdraw 2
    }
    
    function test_RevertTokenMismatch() public {
        vm.prank(alice);
        pool.deposit{value: 1 ether}(111, 1 ether, address(0), hex"");
        
        uint256[] memory publicInputsU = new uint256[](7);
        publicInputsU[0] = pool.currentRoot();
        publicInputsU[3] = 1 ether;
        publicInputsU[4] = 0; // proof says ETH
        publicInputsU[5] = uint256(uint160(bob));
        publicInputsU[6] = pool.poolId();
        
        vm.expectRevert(VoidgunPool.TokenMismatch.selector);
        pool.withdraw(toBytes32Array(publicInputsU), hex"00", bob, address(token), 1 ether); // but passing token
    }
    
    function test_RevertRecipientMismatch() public {
        vm.prank(alice);
        pool.deposit{value: 1 ether}(111, 1 ether, address(0), hex"");
        
        uint256[] memory publicInputsU = new uint256[](7);
        publicInputsU[0] = pool.currentRoot();
        publicInputsU[1] = 444;
        publicInputsU[2] = 555;
        publicInputsU[3] = 1 ether;
        publicInputsU[4] = 0;
        publicInputsU[5] = uint256(uint160(bob)); // proof says bob
        publicInputsU[6] = pool.poolId();
        
        vm.expectRevert(VoidgunPool.RecipientMismatch.selector);
        pool.withdraw(toBytes32Array(publicInputsU), hex"00", alice, address(0), 1 ether); // but trying to send to alice
    }
    
    function test_RevertInvalidRecipient() public {
        vm.prank(alice);
        pool.deposit{value: 1 ether}(111, 1 ether, address(0), hex"");
        
        uint256[] memory publicInputsU = new uint256[](7);
        publicInputsU[0] = pool.currentRoot();
        publicInputsU[6] = pool.poolId();
        
        vm.expectRevert(VoidgunPool.InvalidRecipient.selector);
        pool.withdraw(toBytes32Array(publicInputsU), hex"00", address(0), address(0), 1 ether);
    }
}
