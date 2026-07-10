// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {Test, console} from "forge-std/Test.sol";
import {WebAuthnP256PublicKeyIndex} from "../src/WebAuthnP256PublicKeyIndex.sol";

contract GetAddressTest is Test {
    function test_showAddress() public {
        WebAuthnP256PublicKeyIndex idx = new WebAuthnP256PublicKeyIndex();
        console.log("contract address:", address(idx));
        console.log("chain id:", block.chainid);
    }
}
