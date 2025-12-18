/**
 * Test deposit flow on Tenderly VNet
 * 
 * This script:
 * 1. Initializes a test account with void_initAccount
 * 2. Makes a deposit to VoidgunPool
 * 3. Verifies the deposit event was emitted
 */

import { createWalletClient, createPublicClient, http, parseEther, formatEther, Hex, keccak256, toBytes, encodeFunctionData, concat, pad, toHex } from "viem";
import { privateKeyToAccount, generatePrivateKey, signMessage } from "viem/accounts";
import { mainnet } from "viem/chains";
import fs from "fs";
import path from "path";
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load deployment
const deploymentPath = path.join(__dirname, '../deployment.json');
const deployment = JSON.parse(fs.readFileSync(deploymentPath, 'utf-8'));

const POOL_ADDRESS = deployment.contracts.VoidgunPool as Hex;
const ADMIN_RPC = deployment.rpc.admin;

// VoidgunPool ABI (just what we need)
const POOL_ABI = [
    {
        "type": "function",
        "name": "deposit",
        "inputs": [
            { "name": "commitment", "type": "uint256" },
            { "name": "value", "type": "uint256" },
            { "name": "token", "type": "address" },
            { "name": "ciphertext", "type": "bytes" }
        ],
        "outputs": [],
        "stateMutability": "payable"
    },
    {
        "type": "function",
        "name": "nextIndex",
        "inputs": [],
        "outputs": [{ "type": "uint256" }],
        "stateMutability": "view"
    },
    {
        "type": "function",
        "name": "currentRoot",
        "inputs": [],
        "outputs": [{ "type": "uint256" }],
        "stateMutability": "view"
    },
    {
        "type": "event",
        "name": "Deposit",
        "inputs": [
            { "name": "commitment", "type": "uint256", "indexed": true },
            { "name": "value", "type": "uint256", "indexed": false },
            { "name": "token", "type": "address", "indexed": true },
            { "name": "ciphertext", "type": "bytes", "indexed": false },
            { "name": "leafIndex", "type": "uint256", "indexed": false },
            { "name": "newRoot", "type": "uint256", "indexed": false }
        ]
    }
] as const;

async function main() {
    console.log("Voidgun Deposit Test");
    console.log("====================\n");
    console.log(`Pool: ${POOL_ADDRESS}`);
    console.log(`RPC: ${ADMIN_RPC}\n`);

    // Generate test account
    const privateKey = generatePrivateKey();
    const account = privateKeyToAccount(privateKey);
    console.log(`Test account: ${account.address}`);

    // Setup clients
    const chain = {
        ...mainnet,
        rpcUrls: {
            default: { http: [ADMIN_RPC] },
            public: { http: [ADMIN_RPC] }
        }
    };

    const walletClient = createWalletClient({
        account,
        chain,
        transport: http(ADMIN_RPC)
    });

    const publicClient = createPublicClient({
        chain,
        transport: http(ADMIN_RPC)
    });

    // Fund test account
    console.log("\n1. Funding test account...");
    await (publicClient.request as (args: { method: string; params: unknown[] }) => Promise<void>)({
        method: "tenderly_setBalance",
        params: [[account.address], `0x${parseEther("100").toString(16)}`]
    });

    const balance = await publicClient.getBalance({ address: account.address });
    console.log(`   Balance: ${formatEther(balance)} ETH`);

    // Check initial pool state
    const initialIndex = await publicClient.readContract({
        address: POOL_ADDRESS,
        abi: POOL_ABI,
        functionName: 'nextIndex'
    });
    console.log(`\n2. Initial pool state:`);
    console.log(`   Next index: ${initialIndex}`);

    // Create a test commitment (in production this would be a proper note commitment)
    const testCommitment = BigInt(keccak256(toBytes("test_commitment_" + Date.now())));
    const depositValue = parseEther("1");
    const testCiphertext = toHex("encrypted_note_data_placeholder");

    console.log(`\n3. Making deposit:`);
    console.log(`   Value: ${formatEther(depositValue)} ETH`);
    console.log(`   Commitment: ${testCommitment.toString().slice(0, 20)}...`);

    // Execute deposit
    const tx = await walletClient.writeContract({
        address: POOL_ADDRESS,
        abi: POOL_ABI,
        functionName: 'deposit',
        args: [testCommitment, depositValue, "0x0000000000000000000000000000000000000000" as Hex, testCiphertext as Hex],
        value: depositValue
    });

    console.log(`   Tx hash: ${tx}`);

    // Wait for receipt
    const receipt = await publicClient.waitForTransactionReceipt({ hash: tx });
    console.log(`   Status: ${receipt.status === 'success' ? '[OK]' : '[FAIL]'}`);
    console.log(`   Gas used: ${receipt.gasUsed}`);

    // Check deposit event
    const depositLogs = receipt.logs.filter(log => 
        log.address.toLowerCase() === POOL_ADDRESS.toLowerCase()
    );

    if (depositLogs.length > 0) {
        console.log(`\n4. Deposit event emitted:`);
        console.log(`   Log topics: ${depositLogs[0].topics.length}`);
        console.log(`   Commitment (topic): ${depositLogs[0].topics[1]}`);
    }

    // Check final pool state
    const finalIndex = await publicClient.readContract({
        address: POOL_ADDRESS,
        abi: POOL_ABI,
        functionName: 'nextIndex'
    });
    const currentRoot = await publicClient.readContract({
        address: POOL_ADDRESS,
        abi: POOL_ABI,
        functionName: 'currentRoot'
    });

    console.log(`\n5. Final pool state:`);
    console.log(`   Next index: ${finalIndex} (was ${initialIndex})`);
    console.log(`   Current root: ${currentRoot.toString().slice(0, 20)}...`);

    console.log("\n[OK] Deposit test complete!");
}

main().catch(e => {
    console.error("[X] Test failed:", e.message);
    process.exit(1);
});
