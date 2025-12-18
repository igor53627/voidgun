/**
 * VoidgunPoolV2 Deployment Script
 * 
 * Deploys VoidgunPoolV2 with separate transfer and withdrawal verifiers.
 * 
 * Usage: npx tsx scripts/DeployV2.ts
 */

import { createWalletClient, createPublicClient, http, parseEther, formatEther, Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { mainnet } from "viem/chains";
import fs from "fs";
import path from "path";
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load existing deployment if available
const deploymentPath = path.join(__dirname, '../deployment_v2.json');

// RPC URLs
const TENDERLY_ADMIN_RPC = "https://virtual.mainnet.eu.rpc.tenderly.co/0c523439-45ce-414e-8d7a-5e198770eccf";
const PUBLIC_RPC = TENDERLY_ADMIN_RPC;

// Generate a random deployer key if not provided
const DEPLOYER_KEY = process.env.PRIVATE_KEY || (() => {
    const randomBytes = new Uint8Array(32);
    crypto.getRandomValues(randomBytes);
    return '0x' + Array.from(randomBytes).map(b => b.toString(16).padStart(2, '0')).join('');
})();

const account = privateKeyToAccount(DEPLOYER_KEY as Hex);

function readArtifact(contractName: string, solFileName?: string, useVerifierProfile = false) {
    const baseDir = path.join(__dirname, "..");
    const outDir = useVerifierProfile ? "out-verifier" : "out";
    const fileName = solFileName || `${contractName}.sol`;
    const artifactPath = path.join(baseDir, outDir, `${fileName}/${contractName}.json`);
    
    if (!fs.existsSync(artifactPath)) {
        throw new Error(`Artifact not found: ${artifactPath}. Run 'forge build' first.`);
    }
    
    const artifact = JSON.parse(fs.readFileSync(artifactPath, 'utf8'));
    if (artifact.bytecode?.object) {
        artifact.bytecode = artifact.bytecode.object;
    }
    return artifact;
}

async function main() {
    console.log("VoidgunPoolV2 Deployment");
    console.log("========================\n");
    
    const chain = {
        ...mainnet,
        rpcUrls: {
            default: { http: [PUBLIC_RPC!] },
            public: { http: [PUBLIC_RPC!] }
        }
    };
    
    const walletClient = createWalletClient({
        account,
        chain,
        transport: http(PUBLIC_RPC)
    });
    
    const publicClient = createPublicClient({
        chain,
        transport: http(PUBLIC_RPC)
    });
    
    const adminClient = createWalletClient({
        chain,
        transport: http(TENDERLY_ADMIN_RPC)
    });
    
    async function fundAccount(address: string, amountEth = "1000") {
        console.log(`Funding ${address} with ${amountEth} ETH...`);
        try {
            await (adminClient.request as (args: { method: string; params: unknown[] }) => Promise<void>)({
                method: "tenderly_setBalance",
                params: [[address], `0x${parseEther(amountEth).toString(16)}`]
            });
        } catch (e) {
            console.error(`Failed to fund ${address}:`, e);
        }
    }
    
    async function mineBlocks(count = 1) {
        try {
            await (adminClient.request as (args: { method: string; params: unknown[] }) => Promise<void>)({
                method: "evm_increaseBlocks",
                params: [`0x${count.toString(16)}`]
            });
        } catch { /* ignore */ }
    }
    
    console.log(`Deployer: ${account.address}\n`);
    
    // Fund deployer
    await fundAccount(account.address);
    await mineBlocks(1);
    
    const balance = await publicClient.getBalance({ address: account.address });
    console.log(`Deployer balance: ${formatEther(balance)} ETH\n`);
    
    // 1. Deploy Poseidon2
    console.log("1. Deploying Poseidon2...");
    const poseidon2Artifact = readArtifact("Poseidon2Yul", "Poseidon2.sol");
    const poseidon2Hash = await walletClient.deployContract({
        abi: poseidon2Artifact.abi,
        bytecode: poseidon2Artifact.bytecode as Hex,
        args: []
    });
    await mineBlocks(1);
    const poseidon2Receipt = await publicClient.waitForTransactionReceipt({ hash: poseidon2Hash });
    const poseidon2Address = poseidon2Receipt.contractAddress!;
    console.log(`   Poseidon2: ${poseidon2Address}`);
    
    // 2. Deploy TransferVerifier
    console.log("2. Deploying TransferVerifier...");
    const transferVerifierArtifact = readArtifact("HonkVerifier", "TransferVerifier.sol", true);
    const transferVerifierHash = await walletClient.deployContract({
        abi: transferVerifierArtifact.abi,
        bytecode: transferVerifierArtifact.bytecode as Hex,
        args: []
    });
    await mineBlocks(1);
    const transferVerifierReceipt = await publicClient.waitForTransactionReceipt({ hash: transferVerifierHash });
    const transferVerifierAddress = transferVerifierReceipt.contractAddress!;
    console.log(`   TransferVerifier: ${transferVerifierAddress}`);
    
    // 3. Deploy WithdrawalVerifier
    console.log("3. Deploying WithdrawalVerifier...");
    const withdrawalVerifierArtifact = readArtifact("WithdrawalVerifier", "WithdrawalVerifier.sol", true);
    const withdrawalVerifierHash = await walletClient.deployContract({
        abi: withdrawalVerifierArtifact.abi,
        bytecode: withdrawalVerifierArtifact.bytecode as Hex,
        args: []
    });
    await mineBlocks(1);
    const withdrawalVerifierReceipt = await publicClient.waitForTransactionReceipt({ hash: withdrawalVerifierHash });
    const withdrawalVerifierAddress = withdrawalVerifierReceipt.contractAddress!;
    console.log(`   WithdrawalVerifier: ${withdrawalVerifierAddress}`);
    
    // 4. Deploy VoidgunPoolV2
    console.log("4. Deploying VoidgunPoolV2...");
    const poolArtifact = readArtifact("VoidgunPoolV2");
    const poolHash = await walletClient.deployContract({
        abi: poolArtifact.abi,
        bytecode: poolArtifact.bytecode as Hex,
        args: [transferVerifierAddress, withdrawalVerifierAddress, poseidon2Address]
    });
    await mineBlocks(1);
    const poolReceipt = await publicClient.waitForTransactionReceipt({ hash: poolHash });
    const poolAddress = poolReceipt.contractAddress!;
    console.log(`   VoidgunPoolV2: ${poolAddress}`);
    
    // Get pool ID
    const poolId = await publicClient.readContract({
        address: poolAddress as Hex,
        abi: poolArtifact.abi,
        functionName: 'poolId'
    });
    console.log(`   Pool ID: ${poolId}`);
    
    console.log("\n[OK] Deployment Complete!");
    console.log("=========================");
    console.log(`  Poseidon2:           ${poseidon2Address}`);
    console.log(`  TransferVerifier:    ${transferVerifierAddress}`);
    console.log(`  WithdrawalVerifier:  ${withdrawalVerifierAddress}`);
    console.log(`  VoidgunPoolV2:       ${poolAddress}`);
    console.log(`  Pool ID:             ${poolId}`);
    
    // Save deployment info
    const output = {
        contracts: {
            Poseidon2: poseidon2Address,
            TransferVerifier: transferVerifierAddress,
            WithdrawalVerifier: withdrawalVerifierAddress,
            VoidgunPoolV2: poolAddress,
        },
        poolId: poolId?.toString(),
        rpc: {
            public: PUBLIC_RPC,
            admin: TENDERLY_ADMIN_RPC
        },
        chainId: 1,
        deployer: account.address,
    };
    
    fs.writeFileSync(deploymentPath, JSON.stringify(output, null, 2));
    console.log(`\nWrote deployment info to ${deploymentPath}`);
}

main().catch(e => {
    console.error("[X] Deployment failed:", e.message);
    process.exit(1);
});
