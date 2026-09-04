import unittest

from src.model_checker.models.call_emulator import CallEmulator
from src.model_checker.models.wrappers import MemoryAddress


class CallEmulatorMemoryAddressTests(unittest.TestCase):
    def setUp(self):
        self.emulator = CallEmulator.__new__(CallEmulator)
        self.with_delta = self.emulator._CallEmulator__memory_address_with_delta

    def test_memory_address_delta_returns_adjusted_copy(self):
        address = MemoryAddress.__new__(MemoryAddress)
        address.base_register = "rbp"
        address.index_register = None
        address.scale = None
        address.displacement = -16

        adjusted = self.with_delta(address, 4)

        self.assertIsNot(adjusted, address)
        self.assertEqual(adjusted.base_register, "rbp")
        self.assertEqual(adjusted.displacement, -12)
        self.assertEqual(address.displacement, -16)

    def test_rsp_sentinel_survives_pointer_arithmetic(self):
        self.assertEqual(self.with_delta("rsp", 8), "rsp")


if __name__ == "__main__":
    unittest.main()
