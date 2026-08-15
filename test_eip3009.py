import unittest

from eip3009 import (
    EIP3009Domain, build_transfer_authorization, resolve_domain,
    TRANSFER_WITH_AUTHORIZATION_TYPE, EIP712_DOMAIN_TYPE,
)

FROM_ADDR = "0x1111111111111111111111111111111111111111"
TO_ADDR = "0x2222222222222222222222222222222222222222"


class TestResolveDomain(unittest.TestCase):
    def test_known_usdc_base_resolves(self):
        domain = resolve_domain("USDC", "base")
        self.assertIsNotNone(domain)
        self.assertEqual(domain.chain_id, 8453)
        self.assertEqual(domain.verifying_contract, "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913")

    def test_known_usdc_ethereum_resolves(self):
        domain = resolve_domain("USDC", "ethereum")
        self.assertIsNotNone(domain)
        self.assertEqual(domain.chain_id, 1)

    def test_case_insensitive_lookup(self):
        self.assertEqual(resolve_domain("usdc", "BASE"), resolve_domain("USDC", "base"))

    def test_unrecognized_asset_refuses_to_guess(self):
        self.assertIsNone(resolve_domain("DAI", "base"))

    def test_unrecognized_network_refuses_to_guess(self):
        self.assertIsNone(resolve_domain("USDC", "some-other-chain"))


class TestBuildTransferAuthorization(unittest.TestCase):
    def setUp(self):
        self.domain = resolve_domain("USDC", "base")

    def test_structure_matches_eip712_shape(self):
        msg = build_transfer_authorization(self.domain, FROM_ADDR, TO_ADDR, 1_000_000)
        self.assertEqual(set(msg.keys()), {"types", "domain", "primaryType", "message"})
        self.assertEqual(msg["primaryType"], "TransferWithAuthorization")
        self.assertEqual(msg["types"]["TransferWithAuthorization"], TRANSFER_WITH_AUTHORIZATION_TYPE)
        self.assertEqual(msg["types"]["EIP712Domain"], EIP712_DOMAIN_TYPE)

    def test_domain_fields_pass_through_correctly(self):
        msg = build_transfer_authorization(self.domain, FROM_ADDR, TO_ADDR, 1_000_000)
        self.assertEqual(msg["domain"]["name"], "USD Coin")
        self.assertEqual(msg["domain"]["version"], "2")
        self.assertEqual(msg["domain"]["chainId"], 8453)
        self.assertEqual(msg["domain"]["verifyingContract"], self.domain.verifying_contract)

    def test_message_fields(self):
        msg = build_transfer_authorization(self.domain, FROM_ADDR, TO_ADDR, 1_000_000, valid_after=100)
        m = msg["message"]
        self.assertEqual(m["from"], FROM_ADDR)
        self.assertEqual(m["to"], TO_ADDR)
        self.assertEqual(m["value"], 1_000_000)
        self.assertEqual(m["validAfter"], 100)
        self.assertGreater(m["validBefore"], m["validAfter"])

    def test_nonce_is_32_bytes_hex_encoded(self):
        msg = build_transfer_authorization(self.domain, FROM_ADDR, TO_ADDR, 1_000_000)
        nonce = msg["message"]["nonce"]
        self.assertTrue(nonce.startswith("0x"))
        self.assertEqual(len(nonce), 2 + 64)  # 32 bytes = 64 hex chars

    def test_nonce_is_random_across_calls(self):
        msg1 = build_transfer_authorization(self.domain, FROM_ADDR, TO_ADDR, 1_000_000)
        msg2 = build_transfer_authorization(self.domain, FROM_ADDR, TO_ADDR, 1_000_000)
        self.assertNotEqual(msg1["message"]["nonce"], msg2["message"]["nonce"])

    def test_explicit_nonce_is_used_verbatim(self):
        explicit = b"\x01" * 32
        msg = build_transfer_authorization(self.domain, FROM_ADDR, TO_ADDR, 1_000_000, nonce=explicit)
        self.assertEqual(msg["message"]["nonce"], "0x" + "01" * 32)

    def test_valid_for_seconds_controls_window(self):
        msg = build_transfer_authorization(self.domain, FROM_ADDR, TO_ADDR, 1_000_000, valid_for_seconds=60, valid_after=0)
        # validBefore should be ~60s from now, not the default 600.
        import time
        self.assertLess(msg["message"]["validBefore"], int(time.time()) + 70)

    def test_zero_value_rejected(self):
        with self.assertRaises(ValueError):
            build_transfer_authorization(self.domain, FROM_ADDR, TO_ADDR, 0)

    def test_negative_value_rejected(self):
        with self.assertRaises(ValueError):
            build_transfer_authorization(self.domain, FROM_ADDR, TO_ADDR, -100)


if __name__ == "__main__":
    unittest.main()
