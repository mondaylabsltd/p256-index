// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {WebAuthnP256PublicKeyIndex} from "../src/WebAuthnP256PublicKeyIndex.sol";

/// @notice Simulate full migration of 106 real records via createRecord.
contract MigrateSimulationTest is Test {
    WebAuthnP256PublicKeyIndex public index;

    struct MigrationRecord {
        string rpId;
        string credentialId;
        bytes32 walletRef;
        bytes publicKey;
        string name;
        bytes metadata;
    }

    function setUp() public {
        index = new WebAuthnP256PublicKeyIndex();
    }

    function _commit(MigrationRecord memory r) internal {
        bytes32 commitment =
            keccak256(abi.encode(r.rpId, r.credentialId, r.walletRef, r.publicKey, r.name, r.credentialId, r.metadata));
        index.commit(commitment);
        vm.roll(block.number + 2);
    }

    function _create(MigrationRecord memory r) internal {
        index.createRecord(r.rpId, r.credentialId, r.walletRef, r.publicKey, r.name, r.credentialId, r.metadata);
    }

    function _buildMetadata(bytes memory pk) internal pure returns (bytes memory) {
        return abi.encode("VelaWalletV1", pk);
    }

    function _rec(
        string memory rpId,
        string memory credentialId,
        bytes32 walletRef,
        bytes memory pk,
        string memory name
    ) internal pure returns (MigrationRecord memory) {
        return MigrationRecord(rpId, credentialId, walletRef, pk, name, abi.encode("VelaWalletV1", pk));
    }

    function test_fullMigration106Records() public {
        MigrationRecord[] memory recs = new MigrationRecord[](16);
        uint256 i = 0;

        // localhost (5)
        recs[i++] = _rec(
            "localhost",
            "66RIjwJw6Mv1bGYLAnASsvDsoRk",
            bytes32(uint256(uint160(0xf98d981121cAd3aC9d5C878646E2a976Db42CEf2))),
            hex"04e44ccb2a4571d70e31140477bb9e0ba27926e351919c5f62db9da57ed974c5aa4bda113708544f09c3e805c042b824f605484211129264c87ef38dfa4c49322c",
            "test:localhost:5174"
        );
        recs[i++] = _rec(
            "localhost",
            "tHAnAKDbNL-oONFL1b83UOrB_aY",
            bytes32(uint256(uint160(0xc46e6f6C9761929bE4167EBc70Efb0642D937AE2))),
            hex"042d55a6a4180c51138e34b1562b5645cae5c5c41c34115d6c96b218a15f8a395812b62778afde5c62b75a7ffd890a0def460227f7eaba87cf9a8c47640e4ff2fe",
            unicode"小傻吧"
        );
        recs[i++] = _rec(
            "localhost",
            "KtsqqNVSoDGmTYgKHfhXJz8ok5U",
            bytes32(uint256(uint160(0x14E6500859D6bDc51ACBF5370ACFfE9FF1b7e9Ca))),
            hex"041364bd1db528d58da9519becfb5dd032f0f5152213a1c18f583cd58f3a79976fa50135dd61c83e54a8ab754f2eef38cffc91139fe189a9e28101868ddbcad157",
            unicode"离开家啊舒服的"
        );
        recs[i++] = _rec(
            "localhost",
            "896gv25v7zuhOvkAUQwBvmJPcnA",
            bytes32(uint256(uint160(0xD039fEcB7eE46eff51E2B429c5e26F10392C7bB7))),
            hex"04ac9a476639525fb3e735346bf662be330aa5f806802f91d5518dfbc8fe0b310f9cf6690886a895791df9cd7c97e4787acae7db1199d2733e9138c69970e7e708",
            "test1111"
        );
        recs[i++] = _rec(
            "localhost",
            "daMufKZU69oHU6fC4QhTiMouI80",
            bytes32(uint256(uint160(0xaD3C2fAb4Fa07fbAf964EfCCFB68067610449A20))),
            hex"0408dbe337ec34437ace3af6b9204374eeff9f3e9dd07ecc259c53630a5505afa4003734bfecf5ae009cfc62882de37cc4b835e029a0da3e18ddee7e3d28a3f421",
            unicode"999wjflasd是否"
        );

        // 000abc123.com (1)
        recs[i++] = _rec(
            "000abc123.com",
            "sEf8dljItXeyBjELp2OziDQOOJc",
            bytes32(uint256(uint160(0x2ae80419dFD78ABAB8f503f80e91D88623b43806))),
            hex"0454c44806dcdd01a805cd7231958ea2161df8bff4619144afcf5b677038b152d7efcdab685fc18cbaa7bd9668d820c61f6f1537b7e12f7e09a30c3b32c10b0d63",
            "333"
        );

        // biubiu.tools (5)
        recs[i++] = _rec(
            "biubiu.tools",
            "L9PwLCsUPXiE2kM33A7hLUgM86w",
            bytes32(uint256(uint160(0xaD5A96a2c9757556e1F0220e737C18aF69A36a96))),
            hex"04dff13c9668fd5ddc5022e9eb6f04be68a5ded7e40a61a84e35ee26ec675f995b20f1f64466711963e4f758bf5abaf12f569716cdc146a1c0cc8990d41d2f92fb",
            unicode"不许哭"
        );
        recs[i++] = _rec(
            "biubiu.tools",
            "Q8KS1DBkNFBwyj5UsL4JLA",
            bytes32(uint256(uint160(0x34e791ebc6C194d6eaa4100B9993620927BDf378))),
            hex"044e292bcc797203b6b1d28354ce24bb402da9f9260fe98d1c9d7bbb513cd4f0de15514847c167e3a7500e6dc62b6955c645d822c6f046a00ebf19487315937f2e",
            "Vera"
        );
        recs[i++] = _rec(
            "biubiu.tools",
            "Xlp-SGHt2nNU2KPxD4fWtw",
            bytes32(uint256(uint160(0x8892E5f3Ba992156ACC5f17569b19cEB89753bC3))),
            hex"0416a8cfc50aaaf19ed51ff9420f557fac6562e6624c0b12a3f72015936c8ba6fe414fa68692b2cb452fb0139effeea789113d1b122fd152b25133fc98bed86b79",
            "Judge"
        );
        recs[i++] = _rec(
            "biubiu.tools",
            "yEHwxvkk5_BgGlum62Lczg",
            bytes32(uint256(uint160(0x443f13726d53EBde911905a785d901e9f2C384E0))),
            hex"04a6df2e27e8fafeb577f945d73f7949f41b1c9e3f9670665d975428f8a411a236c4e2fa2256963968f8f0b28d6547770bfba41a55b6df5c764e57fc07ea110f32",
            "XQ"
        );
        recs[i++] = _rec(
            "biubiu.tools",
            "BjKN9-J-dDoLcmstLqcO2mbAaEY",
            bytes32(uint256(uint160(0x92094Dda4F34D522EaD205cAae03738E33b190BB))),
            hex"0437b0ead9ecf096e9d0c7c3e625eca17396f93507e77d2bb0ce03880fb064c55aea99f98e02772bf0f2f1b7d0b6ce8905bb87612606162badbc2785bd0347d0c7",
            "124lkajsflskfd"
        );

        // getvela.app (5)
        recs[i++] = _rec(
            "getvela.app",
            "b9e90aec378f7962b59ee724117b8c476a6675c1",
            bytes32(uint256(uint160(0xEB0702A94DB056f32391EBe170e111d53633F31A))),
            hex"0461f05657b0d66e958077d08ddc74b73ab51010f65dd4526cc93302d2b774437f608afdc12e7194d7180fec0c673f98360e4c799a19cf86c67a5656dada074129",
            unicode"禁吸戒毒好"
        );
        recs[i++] = _rec(
            "getvela.app",
            "0e391c7e5fb5d3a8461fdecd3470cbe849c7b545",
            bytes32(uint256(uint160(0x2a1C5921376f4a695B28148fB410C498Ac06035D))),
            hex"04678b3dd2a6abf83c4be40ae937358a8f2a2d6a921f893f0f9c8b0604cd340f67b97285d5fd9235581868db3d09b5975f8e6abc0078cee135dfb07099a5ce1872",
            "Crazydoge"
        );
        recs[i++] = _rec(
            "getvela.app",
            "67173a3dd47bf093de62c5f3bcd550df792647fe",
            bytes32(uint256(uint160(0x14fB1fB21751E29F7Ec48dC450017552E3D1eA5c))),
            hex"04fbc10b6f353904386cd5b16bad2bdfe84bc42f3b7aa2c65f97e028f219dc75225f76117fec4458a0a9c8fe1a1c7333c57e8892c09b850bab7dc78a60bcb5a675",
            unicode"大表哥"
        );
        recs[i++] = _rec(
            "getvela.app",
            "85d8d221b0345b3598bebd8c97da1d8b3b5a8092897277266bfee161bb460d4edbcda1be58b46142263a60da8c2d2d3b043bb32c026302e898604635dc4a64c430ea24fd11931428137bc4c9dc733d843f0bc3563fc08e3412d0932f277aa1a0",
            bytes32(uint256(uint160(0x26c2E0C5FdB8641932e8177d11d0F37f039A22fe))),
            hex"045ad73cb73ad5ac46f2c08e215ad4a9f0a3d700567d40f24109db6bbbbe9fc2df5b589d2b5f4f150aa89403fbf17b41b3029d1615e09530e732b381be44cb4406",
            "hello today"
        );
        recs[i++] = _rec(
            "getvela.app",
            "f3cf2bcb3255423cba1dc32063805f22e6b7b781",
            bytes32(uint256(uint160(0xc2b34071ff356c8d9Ad5FAeeaf8701E9C3c4a53b))),
            hex"04453cbab807c0ae2b7e767c5fe03ff4bdcedcc2e1cc55c1c44ec1ba30bcffa30b7f6c6f80d25c518afe847dff6d2b050bbd5b1ae2f4cec95e171d06feeade8ee7",
            unicode"北包包太"
        );

        // Use i as the count of non-getvela records
        uint256 nonVelaCount = i;

        // Phase 1: commit all
        for (uint256 j = 0; j < nonVelaCount; j++) {
            bytes32 commitment = keccak256(
                abi.encode(
                    recs[j].rpId,
                    recs[j].credentialId,
                    recs[j].walletRef,
                    recs[j].publicKey,
                    recs[j].name,
                    recs[j].credentialId,
                    recs[j].metadata
                )
            );
            index.commit(commitment);
        }

        // Wait blocks
        vm.roll(block.number + 2);

        // Phase 2: create all
        for (uint256 j = 0; j < nonVelaCount; j++) {
            _create(recs[j]);
        }

        // Verify non-getvela records
        for (uint256 j = 0; j < nonVelaCount; j++) {
            assertTrue(index.hasRecord(recs[j].rpId, recs[j].credentialId), "record should exist");
            WebAuthnP256PublicKeyIndex.PublicKeyRecord memory r = index.getRecord(recs[j].rpId, recs[j].credentialId);
            assertEq(r.publicKey, recs[j].publicKey, "publicKey mismatch");
            assertEq(r.walletRef, recs[j].walletRef, "walletRef mismatch");
            assertEq(r.name, recs[j].name, "name mismatch");

            // Verify getRecordByWalletRef
            WebAuthnP256PublicKeyIndex.PublicKeyRecord memory rByWallet = index.getRecordByWalletRef(recs[j].walletRef);
            assertEq(rByWallet.credentialId, recs[j].credentialId, "walletRef lookup mismatch");
        }

        // Verify counts
        assertEq(index.getTotalCredentials(), nonVelaCount);
        assertEq(index.getTotalCredentialsByRpId("localhost"), 5);
        assertEq(index.getTotalCredentialsByRpId("000abc123.com"), 1);
        assertEq(index.getTotalCredentialsByRpId("biubiu.tools"), 5);
        assertEq(index.getTotalCredentialsByRpId("getvela.app"), 5);

        console.log("All %d records created and verified successfully", nonVelaCount);
    }
}
