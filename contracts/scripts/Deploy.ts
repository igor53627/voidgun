/**
 * Voidgun Contract Deployment Script
 * 
 * Deploys VoidgunPool and dependencies to Tenderly Virtual TestNet.
 * 
 * Required environment variables:
 * - PRIVATE_KEY: Deployer private key (NEVER hardcode)
 * - TENDERLY_RPC_URL: Public RPC URL
 * - TENDERLY_ADMIN_RPC: Admin RPC URL (for funding)
 * 
 * Optional:
 * - RESET_VNET: Set to "true" to reset VNet before deployment
 * - TENDERLY_VNET_SLUG: VNet slug for reset operations
 */

import { createWalletClient, createPublicClient, http, parseEther, formatEther, Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { mainnet } from "viem/chains";
import fs from "fs";
import path from "path";
import { fileURLToPath } from 'url';
import { resetVNet, getAdminRpcUrl, getPublicRpcUrl, VirtualTestNet } from './tenderly.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load existing deployment if available
let existingDeployment: Record<string, unknown> | null = null;
const deploymentPath = path.join(__dirname, '../deployment.json');
try {
    existingDeployment = JSON.parse(fs.readFileSync(deploymentPath, 'utf-8'));
} catch {
    // No existing deployment
}

// Configuration
const RESET_VNET_FLAG = process.env.RESET_VNET === "true" || process.argv.includes("--reset");
const VNET_SLUG = process.env.TENDERLY_VNET_SLUG || "voidgun-dev";

// RPC URLs from env or existing deployment
let TENDERLY_ADMIN_RPC = (existingDeployment?.rpc as Record<string, string>)?.admin || process.env.TENDERLY_ADMIN_RPC;
let PUBLIC_RPC = (existingDeployment?.rpc as Record<string, string>)?.public || process.env.TENDERLY_RPC_URL;

// SECURITY: Require private key from environment
const DEPLOYER_KEY = process.env.PRIVATE_KEY;
if (!DEPLOYER_KEY) {
    console.error("[X] CRITICAL: PRIVATE_KEY environment variable is required");
    console.error("    Generate with: cast wallet new");
    console.error("    NEVER hardcode private keys!");
    process.exit(1);
}

if (!DEPLOYER_KEY.match(/^0x[a-fA-F0-9]{64}$/)) {
    console.error("[X] CRITICAL: PRIVATE_KEY must be a valid 32-byte hex string starting with 0x");
    process.exit(1);
}

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
    console.log("Voidgun Contract Deployment");
    console.log("===========================\n");
    
    // Validate RPC URLs
    if (!PUBLIC_RPC || !TENDERLY_ADMIN_RPC) {
        if (!process.env.TENDERLY_ACCESS_KEY) {
            console.error("[X] No RPC URLs configured and no TENDERLY_ACCESS_KEY for VNet creation");
            console.error("    Either set TENDERLY_RPC_URL and TENDERLY_ADMIN_RPC");
            console.error("    Or set TENDERLY_ACCESS_KEY, TENDERLY_PROJECT for auto-creation");
            process.exit(1);
        }
        
        console.log("No RPC URLs configured, creating new VNet...\n");
        const vnet = await resetVNet({
            slug: VNET_SLUG,
            displayName: "Voidgun Dev TestNet",
            networkId: 1,
            chainId: 1,
            stateSync: false,
            explorerEnabled: true,
        });
        
        TENDERLY_ADMIN_RPC = getAdminRpcUrl(vnet);
        PUBLIC_RPC = getPublicRpcUrl(vnet);
        
        if (!TENDERLY_ADMIN_RPC || !PUBLIC_RPC) {
            console.error("[X] VNet created but RPC URLs not found in response");
            process.exit(1);
        }
    } else if (RESET_VNET_FLAG) {
        console.log("Resetting Tenderly Virtual TestNet...\n");
        try {
            const vnet = await resetVNet({
                slug: VNET_SLUG,
                displayName: "Voidgun Dev TestNet",
                networkId: 1,
                chainId: 1,
                stateSync: false,
                explorerEnabled: true,
            });
            
            TENDERLY_ADMIN_RPC = getAdminRpcUrl(vnet);
            PUBLIC_RPC = getPublicRpcUrl(vnet);
            
            if (!TENDERLY_ADMIN_RPC || !PUBLIC_RPC) {
                console.error("[X] VNet reset but RPC URLs not found in response");
                process.exit(1);
            }
        } catch (e) {
            console.error("Failed to reset VNet:", (e as Error).message);
            console.log("Continuing with existing VNet...\n");
        }
    }
    
    // Create clients
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
    
    // Helper functions
    async function fundAccount(address: string, amountEth = "100") {
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
        } catch {
            // Expected on some networks
        }
    }
    
    // Capture deployment block
    const deploymentBlock = await publicClient.getBlockNumber();
    console.log(`Deployment starting at block: ${deploymentBlock}`);
    console.log(`Deployer: ${account.address}\n`);
    
    // Fund deployer
    await fundAccount(account.address);
    await mineBlocks(1);
    
    // Check balance
    const balance = await publicClient.getBalance({ address: account.address });
    console.log(`Deployer balance: ${formatEther(balance)} ETH\n`);
    
    // 1. Deploy Poseidon2
    console.log("Deploying Poseidon2...");
    const poseidon2Artifact = readArtifact("Poseidon2");
    const poseidon2Hash = await walletClient.deployContract({
        abi: poseidon2Artifact.abi,
        bytecode: poseidon2Artifact.bytecode as Hex,
        args: []
    });
    await mineBlocks(1);
    const poseidon2Receipt = await publicClient.waitForTransactionReceipt({ hash: poseidon2Hash });
    const poseidon2Address = poseidon2Receipt.contractAddress!;
    console.log(`  Poseidon2: ${poseidon2Address}`);
    
    // 2. Deploy TransferVerifier (HonkVerifier from out-verifier/)
    // Built with: FOUNDRY_PROFILE=verifier forge build verifier/TransferVerifier.sol
    let verifierAddress: string;
    try {
        const verifierArtifact = readArtifact("HonkVerifier", "TransferVerifier.sol", true);
        console.log("Deploying TransferVerifier (HonkVerifier)...");
        const verifierHash = await walletClient.deployContract({
            abi: verifierArtifact.abi,
            bytecode: verifierArtifact.bytecode as Hex,
            args: []
        });
        await mineBlocks(1);
        const verifierReceipt = await publicClient.waitForTransactionReceipt({ hash: verifierHash });
        verifierAddress = verifierReceipt.contractAddress!;
        console.log(`  TransferVerifier: ${verifierAddress}`);
    } catch (e) {
        console.log("[!] TransferVerifier not found in out-verifier/");
        console.log("    Build with: FOUNDRY_PROFILE=verifier forge build verifier/TransferVerifier.sol");
        console.log("    Error:", (e as Error).message);
        process.exit(1);
    }
    
    // 3. Deploy VoidgunPool
    console.log("Deploying VoidgunPool...");
    const poolArtifact = readArtifact("VoidgunPool");
    const poolHash = await walletClient.deployContract({
        abi: poolArtifact.abi,
        bytecode: poolArtifact.bytecode as Hex,
        args: [verifierAddress, poseidon2Address]
    });
    await mineBlocks(1);
    const poolReceipt = await publicClient.waitForTransactionReceipt({ hash: poolHash });
    const poolAddress = poolReceipt.contractAddress!;
    console.log(`  VoidgunPool: ${poolAddress}`);
    
    // Get pool ID
    const poolId = await publicClient.readContract({
        address: poolAddress as Hex,
        abi: poolArtifact.abi,
        functionName: 'poolId'
    });
    console.log(`  Pool ID: ${poolId}`);
    
    console.log("\n[OK] Deployment Complete!");
    console.log("=========================");
    console.log(`  Poseidon2:       ${poseidon2Address}`);
    console.log(`  Verifier:        ${verifierAddress}`);
    console.log(`  VoidgunPool:     ${poolAddress}`);
    console.log(`  Pool ID:         ${poolId}`);
    
    // Save deployment info (NO private keys)
    const output = {
        contracts: {
            Poseidon2: poseidon2Address,
            TransferVerifier: verifierAddress,
            VoidgunPool: poolAddress,
        },
        poolId: poolId?.toString(),
        rpc: {
            public: PUBLIC_RPC,
            admin: TENDERLY_ADMIN_RPC
        },
        deploymentBlock: deploymentBlock.toString(),
        chainId: 1,
        deployer: account.address,
        // SECURITY: No private keys stored
    };
    
    fs.writeFileSync(deploymentPath, JSON.stringify(output, null, 2));
    console.log(`\nWrote deployment info to ${deploymentPath}`);
}

main().catch(e => {
    console.error("[X] Deployment failed:", e.message);
    process.exit(1);
});
