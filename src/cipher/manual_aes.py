"""
Manual AES-128 implementation for leakage/fault-analysis experiments.

AES-128 structure:
    Initial: AddRoundKey
    Rounds 1-9:
        SubBytes -> ShiftRows -> MixColumns -> AddRoundKey
    Round 10:
        SubBytes -> ShiftRows -> AddRoundKey

State representation:
    16 bytes in AES column-major order:
        state[r + 4*c]

"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


# AES S-box
SBOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
    0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
    0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
    0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
    0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
    0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
    0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
    0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
    0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
    0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
    0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

RCON = (
    0x00, 0x01, 0x02, 0x04, 0x08,
    0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
)


@dataclass(frozen=True)
class AESStage:
    """One observable AES internal stage."""

    round: int
    stage: str
    state: bytes


class ManualAES128:
    """Pure-Python AES-128 with complete internal-state tracing."""

    def __init__(self, key: bytes):
        if len(key) != 16:
            raise ValueError("AES-128 requires exactly 16 key bytes.")

        self.key = bytes(key)
        self.round_keys = self._expand_key(self.key)

    # ------------------------------------------------------------------
    # Basic representation helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _check_block(block: bytes) -> None:
        if len(block) != 16:
            raise ValueError("AES plaintext must be exactly 16 bytes.")

    @staticmethod
    def _add_round_key(state: List[int], key: bytes) -> List[int]:
        return [a ^ b for a, b in zip(state, key)]

    @staticmethod
    def _sub_bytes(state: List[int]) -> List[int]:
        return [SBOX[x] for x in state]

    @staticmethod
    def _shift_rows(state: List[int]) -> List[int]:
        # State is column-major:
        # [s00,s10,s20,s30,s01,s11,s21,s31,...]
        out = [0] * 16

        for row in range(4):
            for col in range(4):
                src_col = (col + row) % 4
                out[4 * col + row] = state[4 * src_col + row]

        return out

    @staticmethod
    def _gmul(a: int, b: int) -> int:
        """GF(2^8) multiplication used by MixColumns."""
        result = 0

        for _ in range(8):
            if b & 1:
                result ^= a

            high_bit = a & 0x80
            a = (a << 1) & 0xFF

            if high_bit:
                a ^= 0x1B

            b >>= 1

        return result

    @classmethod
    def _mix_columns(cls, state: List[int]) -> List[int]:
        out = [0] * 16

        for col in range(4):
            i = 4 * col

            a0, a1, a2, a3 = state[i:i + 4]

            out[i + 0] = (
                cls._gmul(a0, 2) ^
                cls._gmul(a1, 3) ^
                a2 ^
                a3
            )

            out[i + 1] = (
                a0 ^
                cls._gmul(a1, 2) ^
                cls._gmul(a2, 3) ^
                a3
            )

            out[i + 2] = (
                a0 ^
                a1 ^
                cls._gmul(a2, 2) ^
                cls._gmul(a3, 3)
            )

            out[i + 3] = (
                cls._gmul(a0, 3) ^
                a1 ^
                a2 ^
                cls._gmul(a3, 2)
            )

        return out

    # ------------------------------------------------------------------
    # AES-128 key expansion
    # ------------------------------------------------------------------

    @staticmethod
    def _rot_word(word: List[int]) -> List[int]:
        return word[1:] + word[:1]

    @staticmethod
    def _sub_word(word: List[int]) -> List[int]:
        return [SBOX[x] for x in word]

    @classmethod
    def _expand_key(cls, key: bytes) -> List[bytes]:
        """
        Return 11 round keys:
            round_keys[0]  = original key
            round_keys[1]  = round-1 key
            ...
            round_keys[10] = round-10 key
        """
        words: List[List[int]] = [
            list(key[i:i + 4]) for i in range(0, 16, 4)
        ]

        for i in range(4, 44):
            temp = words[i - 1].copy()

            if i % 4 == 0:
                temp = cls._sub_word(cls._rot_word(temp))
                temp[0] ^= RCON[i // 4]

            words.append([
                words[i - 4][j] ^ temp[j]
                for j in range(4)
            ])

        return [
            bytes(sum(words[4 * r:4 * r + 4], []))
            for r in range(11)
        ]

    # ------------------------------------------------------------------
    # State tracing
    # ------------------------------------------------------------------

    @staticmethod
    def _record(
        trace: List[AESStage],
        round_no: int,
        stage: str,
        state: List[int],
    ) -> None:
        trace.append(
            AESStage(
                round=round_no,
                stage=stage,
                state=bytes(state),
            )
        )

    # ------------------------------------------------------------------
    # Fault injection
    # ------------------------------------------------------------------

    @staticmethod
    def _apply_fault(
        state: List[int],
        *,
        byte_index: int,
        fault_value: int,
    ) -> List[int]:
        if not 0 <= byte_index < 16:
            raise ValueError("byte_index must be between 0 and 15.")

        if not 0 <= fault_value <= 0xFF:
            raise ValueError("fault_value must be between 0x00 and 0xFF.")

        faulty = state.copy()
        faulty[byte_index] ^= fault_value
        return faulty

    # ------------------------------------------------------------------
    # Encryption
    # ------------------------------------------------------------------

    def encrypt(
        self,
        plaintext: bytes,
        *,
        fault: Optional[Dict] = None,
        return_trace: bool = False,
    ) -> Tuple[bytes, List[AESStage]] | bytes:
        """
        Encrypt one 16-byte block.

        Parameters
        ----------
        plaintext:
            16-byte AES plaintext.

        fault:
            Optional fault specification. Example:

                {
                    "round": 9,
                    "stage": "after_mix_columns",
                    "byte_index": 0,
                    "fault_value": 0x01,
                }

            The fault is XORed into the selected internal state.

        return_trace:
            If True, return (ciphertext, trace).
            Otherwise return ciphertext only.

        Notes
        -----
        Round numbering follows the AES standard:
            round 0 = initial AddRoundKey
            rounds 1..9 = full rounds
            round 10 = final round

        Therefore, a fault at round 9 is injected while AES is still
        performing encryption, before the final round.
        """
        self._check_block(plaintext)

        if fault is not None:
            self._validate_fault(fault)

        trace: List[AESStage] = []
        state = list(plaintext)

        # ---------------------------
        # Round 0: Initial AddRoundKey
        # ---------------------------
        state = self._add_round_key(state, self.round_keys[0])
        self._record(trace, 0, "add_round_key", state)

        # ---------------------------
        # Rounds 1 through 9
        # ---------------------------
        for round_no in range(1, 10):
            state = self._sub_bytes(state)
            self._record(trace, round_no, "sub_bytes", state)

            state = self._shift_rows(state)
            self._record(trace, round_no, "shift_rows", state)

            state = self._mix_columns(state)
            self._record(trace, round_no, "mix_columns", state)

            # Fault is injected BEFORE AddRoundKey if requested at this
            # stage. This models an internal state fault rather than a
            # post-ciphertext mutation.
            state = self._maybe_fault(
                state,
                fault=fault,
                round_no=round_no,
                stage="after_mix_columns",
                trace=trace,
            )

            state = self._add_round_key(state, self.round_keys[round_no])
            self._record(trace, round_no, "add_round_key", state)

            state = self._maybe_fault(
                state,
                fault=fault,
                round_no=round_no,
                stage="after_add_round_key",
                trace=trace,
            )

        # ---------------------------
        # Round 10: final AES round
        # No MixColumns.
        # ---------------------------
        round_no = 10

        state = self._sub_bytes(state)
        self._record(trace, round_no, "sub_bytes", state)

        state = self._shift_rows(state)
        self._record(trace, round_no, "shift_rows", state)

        state = self._add_round_key(state, self.round_keys[10])
        self._record(trace, round_no, "add_round_key", state)

        state = self._maybe_fault(
            state,
            fault=fault,
            round_no=round_no,
            stage="after_add_round_key",
            trace=trace,
        )

        ciphertext = bytes(state)

        if return_trace:
            return ciphertext, trace

        return ciphertext

    def _maybe_fault(
        self,
        state: List[int],
        *,
        fault: Optional[Dict],
        round_no: int,
        stage: str,
        trace: List[AESStage],
    ) -> List[int]:
        if fault is None:
            return state

        if fault["round"] != round_no:
            return state

        if fault["stage"] != stage:
            return state

        faulty_state = self._apply_fault(
            state,
            byte_index=fault["byte_index"],
            fault_value=fault["fault_value"],
        )

        self._record(trace, round_no, "fault_injected", faulty_state)
        return faulty_state

    @staticmethod
    def _validate_fault(fault: Dict) -> None:
        required = {
            "round",
            "stage",
            "byte_index",
            "fault_value",
        }

        missing = required - set(fault)
        if missing:
            raise ValueError(
                f"Fault specification is missing: {sorted(missing)}"
            )

        if not 0 <= fault["round"] <= 10:
            raise ValueError("Fault round must be between 0 and 10.")

        valid_stages = {
            "after_mix_columns",
            "after_add_round_key",
        }

        if fault["stage"] not in valid_stages:
            raise ValueError(
                f"Unsupported fault stage: {fault['stage']}. "
                f"Use one of {sorted(valid_stages)}."
            )

    # ------------------------------------------------------------------
    # Convenience methods for leakage/fault analysis
    # ------------------------------------------------------------------

    def encrypt_with_trace(
        self,
        plaintext: bytes,
    ) -> Tuple[bytes, List[AESStage]]:
        """Return ciphertext plus every internal AES state."""
        result = self.encrypt(plaintext, return_trace=True)
        return result

    def get_round_state(
        self,
        trace: List[AESStage],
        round_no: int,
        stage: str,
    ) -> bytes:
        """Retrieve one exact internal state from a trace."""
        for item in trace:
            if item.round == round_no and item.stage == stage:
                return item.state

        raise KeyError(
            f"No state found for round={round_no}, stage={stage!r}."
        )


# ----------------------------------------------------------------------
# Simple functional API
# ----------------------------------------------------------------------

def aes128_encrypt(
    plaintext: bytes,
    key: bytes,
    *,
    fault: Optional[Dict] = None,
    return_trace: bool = False,
):
    """Functional wrapper around ManualAES128."""
    aes = ManualAES128(key)
    return aes.encrypt(
        plaintext,
        fault=fault,
        return_trace=return_trace,
    )


# ----------------------------------------------------------------------
# NIST/FIPS-197 known-answer self-test
# ----------------------------------------------------------------------

def self_test() -> None:
    """Run the standard FIPS-197 AES-128 known-answer test."""
    key = bytes.fromhex(
        "000102030405060708090A0B0C0D0E0F"
    )

    plaintext = bytes.fromhex(
        "00112233445566778899AABBCCDDEEFF"
    )

    expected = bytes.fromhex(
        "69C4E0D86A7B0430D8CDB78070B4C55A"
    )

    aes = ManualAES128(key)
    ciphertext, trace = aes.encrypt(
        plaintext,
        return_trace=True,
    )

    assert ciphertext == expected, (
        f"AES self-test failed:\n"
        f"expected: {expected.hex()}\n"
        f"actual:   {ciphertext.hex()}"
    )

    assert len(trace) == 40, f"Unexpected trace length: {len(trace)}"

    r9 = aes.get_round_state(trace, 9, "mix_columns")
    assert len(r9) == 16

    print("Manual AES-128 self-test: PASS")
    print(f"Ciphertext: {ciphertext.hex()}")
    print(f"Captured internal states: {len(trace)}")


# ----------------------------------------------------------------------
# Human-readable state display
# ----------------------------------------------------------------------

def print_state(state: bytes, title: str = "") -> None:
    """
    Print an AES state as a 4x4 matrix.

    AES stores the state column-major:
        state[r + 4*c]

    The displayed matrix is therefore:
        s00 s01 s02 s03
        s10 s11 s12 s13
        s20 s21 s22 s23
        s30 s31 s32 s33
    """
    if len(state) != 16:
        raise ValueError("AES state must contain exactly 16 bytes.")

    if title:
        print(f"\n{title}")

    for row in range(4):
        values = [
            state[4 * col + row]
            for col in range(4)
        ]
        print("  " + " ".join(f"{x:02x}" for x in values))


def print_trace(trace: List[AESStage]) -> None:
    """
    Print every recorded AES internal state.

    Round 9 is explicitly highlighted because it is the intended
    fault-injection round for this project.
    """
    current_round = None

    for item in trace:
        if item.round != current_round:
            current_round = item.round

            if current_round == 0:
                print("\n========== INITIAL TRANSFORMATION ==========")
            elif current_round == 9:
                print("\n========== ROUND 9 -- FAULT TARGET ==========")
            elif current_round == 10:
                print("\n========== ROUND 10 -- FINAL ROUND ==========")
            else:
                print(f"\n========== ROUND {current_round} ==========")

        print_state(
            item.state,
            f"Round {item.round} -> {item.stage}"
        )


# ----------------------------------------------------------------------
# Command-line interface
# ----------------------------------------------------------------------

def _parse_hex_16_bytes(value: str, name: str) -> bytes:
    """
    Parse exactly 32 hexadecimal characters into 16 bytes.

    AES-128 requires both plaintext and key to be exactly 16 bytes.
    """
    value = value.strip().replace(" ", "")

    if len(value) != 32:
        raise argparse.ArgumentTypeError(
            f"{name} must contain exactly 32 hexadecimal characters "
            f"(16 bytes)."
        )

    try:
        result = bytes.fromhex(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"{name} must contain only hexadecimal characters."
        ) from exc

    if len(result) != 16:
        raise argparse.ArgumentTypeError(
            f"{name} must decode to exactly 16 bytes."
        )

    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Manual AES-128 encryption with internal-state tracing. "
            "Useful for leakage and fault-analysis experiments."
        )
    )

    parser.add_argument(
        "--key",
        required=False,
        type=lambda value: _parse_hex_16_bytes(value, "Key"),
        help=(
            "AES-128 key as 32 hexadecimal characters. "
            "Example: 000102030405060708090a0b0c0d0e0f"
        ),
    )

    parser.add_argument(
        "--plaintext",
        required=False,
        type=lambda value: _parse_hex_16_bytes(value, "Plaintext"),
        help=(
            "Plaintext as 32 hexadecimal characters. "
            "Example: 00112233445566778899aabbccddeeff"
        ),
    )

    parser.add_argument(
        "--trace",
        action="store_true",
        help="Print every internal AES state.",
    )

    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run the FIPS-197 AES-128 known-answer test.",
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return

    if args.key is None or args.plaintext is None:
        parser.error(
            "--key and --plaintext are required unless --self-test is used."
        )

    aes = ManualAES128(args.key)

    ciphertext, trace = aes.encrypt(
        args.plaintext,
        return_trace=True,
    )

    print("\n========== AES-128 RESULT ==========")
    print(f"Key:        {args.key.hex()}")
    print(f"Plaintext:  {args.plaintext.hex()}")
    print(f"Ciphertext: {ciphertext.hex()}")

    if args.trace:
        print_trace(trace)


if __name__ == "__main__":
    main()
