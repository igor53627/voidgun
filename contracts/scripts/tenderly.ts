/**
 * Tenderly Virtual TestNet Management
 * 
 * Utilities for creating, deleting, and managing Tenderly Virtual TestNets.
 * 
 * Required environment variables:
 * - TENDERLY_ACCESS_KEY: Your Tenderly API access key
 * - TENDERLY_ACCOUNT: Your Tenderly account slug (e.g., "me" or username)
 * - TENDERLY_PROJECT: Your Tenderly project slug
 */

export interface TenderlyConfig {
    accessKey: string;
    account: string;
    project: string;
}

export interface VirtualTestNet {
    id: string;
    slug: string;
    display_name: string;
    rpcs: Array<{
        name: string;
        url: string;
    }>;
    created_at: string;
}

export interface CreateVNetOptions {
    slug: string;
    displayName: string;
    networkId?: number;
    blockNumber?: string | number;
    chainId?: number;
    stateSync?: boolean;
    explorerEnabled?: boolean;
}

const API_BASE = "https://api.tenderly.co/api/v1";

function getConfig(): TenderlyConfig {
    const accessKey = process.env.TENDERLY_ACCESS_KEY;
    const account = process.env.TENDERLY_ACCOUNT || "me";
    const project = process.env.TENDERLY_PROJECT;

    if (!accessKey) {
        throw new Error("TENDERLY_ACCESS_KEY environment variable is required");
    }
    if (!project) {
        throw new Error("TENDERLY_PROJECT environment variable is required");
    }

    return { accessKey, account, project };
}

async function apiRequest<T>(
    method: string,
    path: string,
    config: TenderlyConfig,
    body?: object
): Promise<T> {
    const url = `${API_BASE}/account/${config.account}/project/${config.project}${path}`;
    
    const response = await fetch(url, {
        method,
        headers: {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Access-Key": config.accessKey,
        },
        body: body ? JSON.stringify(body) : undefined,
    });

    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Tenderly API error (${response.status}): ${errorText}`);
    }

    if (response.status === 204) {
        return {} as T;
    }

    return response.json();
}

export async function listVNets(config?: TenderlyConfig): Promise<VirtualTestNet[]> {
    config = config || getConfig();
    const result = await apiRequest<VirtualTestNet[]>("GET", "/vnets", config);
    return result || [];
}

export async function getVNet(idOrSlug: string, config?: TenderlyConfig): Promise<VirtualTestNet | null> {
    config = config || getConfig();
    try {
        return await apiRequest<VirtualTestNet>("GET", `/vnets/${idOrSlug}`, config);
    } catch (e: unknown) {
        if (e instanceof Error && e.message?.includes("404")) {
            return null;
        }
        throw e;
    }
}

export async function createVNet(options: CreateVNetOptions, config?: TenderlyConfig): Promise<VirtualTestNet> {
    config = config || getConfig();
    
    const body = {
        slug: options.slug,
        display_name: options.displayName,
        fork_config: {
            network_id: options.networkId || 1,
            block_number: options.blockNumber?.toString() || "latest",
        },
        virtual_network_config: {
            chain_config: {
                chain_id: options.chainId || 1,
            },
        },
        sync_state_config: {
            enabled: options.stateSync ?? false,
            commitment_level: "latest",
        },
        explorer_page_config: {
            enabled: options.explorerEnabled ?? true,
            verification_visibility: "bytecode",
        },
    };

    return apiRequest<VirtualTestNet>("POST", "/vnets", config, body);
}

export async function deleteVNet(idOrSlug: string, config?: TenderlyConfig): Promise<void> {
    config = config || getConfig();
    await apiRequest<void>("DELETE", `/vnets/${idOrSlug}`, config);
}

export async function deleteVNetIfExists(idOrSlug: string, config?: TenderlyConfig): Promise<boolean> {
    config = config || getConfig();
    try {
        await deleteVNet(idOrSlug, config);
        return true;
    } catch (e: unknown) {
        if (e instanceof Error && e.message?.includes("404")) {
            return false;
        }
        throw e;
    }
}

export function getAdminRpcUrl(vnet: VirtualTestNet): string | undefined {
    return vnet.rpcs?.find(r => r.name === "Admin RPC")?.url;
}

export function getPublicRpcUrl(vnet: VirtualTestNet): string | undefined {
    return vnet.rpcs?.find(r => r.name === "Public RPC")?.url;
}

export async function resetVNet(options: CreateVNetOptions, config?: TenderlyConfig): Promise<VirtualTestNet> {
    config = config || getConfig();
    
    console.log(`Resetting Virtual TestNet: ${options.slug}...`);
    
    const vnets = await listVNets(config);
    const existing = vnets.find(v => v.slug === options.slug);
    
    if (existing) {
        console.log(`  Found existing VNet: ${existing.id}`);
        await deleteVNet(existing.id, config);
        console.log(`  Deleted existing VNet: ${options.slug}`);
        await new Promise(resolve => setTimeout(resolve, 2000));
    }
    
    console.log(`  Creating new VNet: ${options.slug}...`);
    const vnet = await createVNet(options, config);
    console.log(`  Created VNet: ${vnet.id}`);
    console.log(`  Admin RPC: ${getAdminRpcUrl(vnet)}`);
    console.log(`  Public RPC: ${getPublicRpcUrl(vnet)}`);
    
    return vnet;
}

// CLI interface
if (import.meta.url === `file://${process.argv[1]}`) {
    const command = process.argv[2];
    
    async function main() {
        switch (command) {
            case "list": {
                const vnets = await listVNets();
                console.log("Virtual TestNets:");
                for (const vnet of vnets) {
                    console.log(`  - ${vnet.slug} (${vnet.id})`);
                    console.log(`    Admin RPC: ${getAdminRpcUrl(vnet)}`);
                }
                break;
            }
                
            case "create": {
                const slug = process.argv[3] || `voidgun-dev-${Date.now()}`;
                const vnet = await createVNet({
                    slug,
                    displayName: `Voidgun Dev TestNet`,
                    networkId: 1,
                    chainId: 1,
                    stateSync: false,
                    explorerEnabled: true,
                });
                console.log("Created VNet:", vnet.id);
                console.log("Admin RPC:", getAdminRpcUrl(vnet));
                console.log("Public RPC:", getPublicRpcUrl(vnet));
                break;
            }
                
            case "delete": {
                const idToDelete = process.argv[3];
                if (!idToDelete) {
                    console.error("Usage: tenderly.ts delete <vnet-id-or-slug>");
                    process.exit(1);
                }
                await deleteVNet(idToDelete);
                console.log(`Deleted VNet: ${idToDelete}`);
                break;
            }
                
            case "reset": {
                const resetSlug = process.argv[3] || "voidgun-dev";
                const resetVnet = await resetVNet({
                    slug: resetSlug,
                    displayName: `Voidgun Dev TestNet`,
                    networkId: 1,
                    chainId: 1,
                    stateSync: false,
                    explorerEnabled: true,
                });
                console.log("\nVNet reset complete!");
                console.log("Admin RPC:", getAdminRpcUrl(resetVnet));
                console.log("Public RPC:", getPublicRpcUrl(resetVnet));
                break;
            }
                
            default:
                console.log("Tenderly Virtual TestNet Management");
                console.log("");
                console.log("Usage: npx tsx scripts/tenderly.ts <command> [args]");
                console.log("");
                console.log("Commands:");
                console.log("  list              List all Virtual TestNets");
                console.log("  create [slug]     Create a new Virtual TestNet");
                console.log("  delete <id|slug>  Delete a Virtual TestNet");
                console.log("  reset [slug]      Delete and recreate a Virtual TestNet");
                console.log("");
                console.log("Environment variables:");
                console.log("  TENDERLY_ACCESS_KEY  Your Tenderly API access key (required)");
                console.log("  TENDERLY_ACCOUNT     Your Tenderly account slug (default: 'me')");
                console.log("  TENDERLY_PROJECT     Your Tenderly project slug (required)");
        }
    }
    
    main().catch(e => {
        console.error("Error:", e.message);
        process.exit(1);
    });
}
