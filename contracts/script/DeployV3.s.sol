// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {WebAuthnP256PublicKeyIndexV3} from "../src/WebAuthnP256PublicKeyIndexV3.sol";

contract DeployV3Script is Script {
    function run() public {
        bytes32 salt = vm.envOr("DEPLOY_SALT", bytes32(0));

        vm.startBroadcast();
        WebAuthnP256PublicKeyIndexV3 index = new WebAuthnP256PublicKeyIndexV3{salt: salt}();
        console.log("WebAuthnP256PublicKeyIndexV3 deployed at:", address(index));
        vm.stopBroadcast();
    }
}
