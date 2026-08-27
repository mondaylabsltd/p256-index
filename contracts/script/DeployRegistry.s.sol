// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {WebAuthnP256PublicKeyRegistry} from "../src/WebAuthnP256PublicKeyRegistry.sol";

/// The registry requires the EIP-7951 / RIP-7212 P256VERIFY precompile at
/// 0x100 on the target chain. Forge's fork simulation cannot see chain
/// precompiles, so verify BEFORE deploying with a direct eth_call (this
/// known-valid vector must return 0x...01 — confirmed live on Gnosis):
///
///   cast call 0x0000000000000000000000000000000000000100 --rpc-url $RPC --data \
///   0x3bed8f935df02287586f8cf8f833c06ea4430ee53cac7f1a38d52d3466fb8cbb3cef577bfa8b4cb3c3806846e83393ac1e72f84db9a7e9620dbd1dbf140553579b53ed2a49332b4d287f064fa134c098d4ecd708606e37ece2860a994873c4337cbc77305ada8fd162d867fd836f4af21fccafaa5fd041531ae6b5cd1616bb74b64048cce1baa94ec86cf1394069e34c01c6d2fa966bdaf902b1dff153d08d40
contract DeployRegistryScript is Script {
    function run() public {
        bytes32 salt = vm.envOr("DEPLOY_SALT", bytes32(0));
        // Standalone deployment by default (the registry freezes its own
        // chain id and address as the signature domain). A MIGRATION
        // deployment sets both to the original registry's pair so its
        // historical calldata replays verbatim:
        //   DOMAIN_CHAIN_ID=100 DOMAIN_REGISTRY=0x<original> forge script ...
        uint256 domainChainId = vm.envOr("DOMAIN_CHAIN_ID", uint256(0));
        address domainRegistry = vm.envOr("DOMAIN_REGISTRY", address(0));
        vm.startBroadcast();
        WebAuthnP256PublicKeyRegistry registry =
            new WebAuthnP256PublicKeyRegistry{salt: salt}(domainChainId, domainRegistry);
        console.log("WebAuthnP256PublicKeyRegistry deployed at:", address(registry));
        console.log("  domain chain id:", registry.DOMAIN_CHAIN_ID());
        console.log("  domain registry:", registry.DOMAIN_REGISTRY());
        vm.stopBroadcast();
    }
}
