// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {WebAuthnP256PublicKeyIndex} from "../src/WebAuthnP256PublicKeyIndex.sol";

contract DeployScript is Script {
    function run() public {
        bytes32 salt = vm.envOr("DEPLOY_SALT", bytes32(0));

        vm.startBroadcast();
        WebAuthnP256PublicKeyIndex index = new WebAuthnP256PublicKeyIndex{salt: salt}();
        console.log("WebAuthnP256PublicKeyIndex deployed at:", address(index));
        vm.stopBroadcast();
    }
}
