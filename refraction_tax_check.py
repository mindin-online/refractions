"""
refraction_tax_check.py

0% transfer-tax verification. Deliberately expensive (one extra
simulated call plus a pool balance read), so per your call this only
runs on candidates that have already passed everything else in
refraction_check.py -- not on every scanned token.

THE PROBLEM: some tokens deduct a "tax" on every transfer (a common rug
pattern -- e.g. burns or redirects a % on each send). A plain
balanceOf() read can't reveal this; you have to actually observe a
transfer happen and compare sent vs. received.

THE TECHNIQUE: eth_call supports a "state override" -- for the duration
of one simulated call only (nothing real ever changes), you can
temporarily swap in different bytecode at any address. This uses that to
temporarily place a tiny helper contract (TaxChecker, source below) AT
the liquidity pool's own address. Because the helper now runs AS the
pool, when it calls the token's transfer() function, the token contract
sees the real pool as msg.sender -- which already holds a real balance
on mainnet. No storage-layout guessing, no balance injection, no
multi-step chained calls: before-balance, transfer, after-balance, and
the delta, all atomically in one call.

VERIFIED vs. ASSUMED, to be explicit about confidence:
  - The helper contract compiled successfully (solc 0.8.20) -- real,
    not hypothetical. Its deployed bytecode is embedded below so Railway
    never needs a Solidity compiler at runtime.
  - web3.py 8.0.0's eth.call() genuinely accepts a state_override
    parameter with a "code" field -- confirmed directly against the
    installed library, not assumed from docs.
  - NOT verified: whether Base's specific RPC (whatever RPC_URL points
    at) actually honors stateOverride on eth_call. This is a widely
    supported geth-style extension, but some lightweight/public RPC
    endpoints reject or silently ignore non-standard parameters. This
    is the first thing to check if every tax check comes back
    "inconclusive" -- point RPC_URL at a provider you know supports it
    (Alchemy, Infura, QuickNode) if the default public Base RPC doesn't.

TaxChecker.sol (compiled to the bytecode below):

    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;

    interface IERC20 {
        function balanceOf(address) external view returns (uint256);
        function transfer(address, uint256) external returns (bool);
    }

    contract TaxChecker {
        function testTax(address token, address dummy, uint256 amount)
            external
            returns (uint256 before_, uint256 after_)
        {
            before_ = IERC20(token).balanceOf(dummy);
            IERC20(token).transfer(dummy, amount);
            after_ = IERC20(token).balanceOf(dummy);
        }
    }
"""
import os
from web3 import Web3

RPC_URL = os.environ.get("RPC_URL", "https://mainnet.base.org")
w3 = Web3(Web3.HTTPProvider(RPC_URL))

# Compiled once (solc 0.8.20, optimizer 200 runs) from TaxChecker.sol above.
TAX_CHECKER_DEPLOYED_BYTECODE = bytes.fromhex(
    "608060405234801561000f575f80fd5b5060043610610029575f3560e01c806366e102eb1461002d575b5f80fd5b"
    "61004061003b3660046101c7565b610059565b6040805192835260208301919091520160405180910390f35b6040"
    "516370a0823160e01b81526001600160a01b0383811660048301525f9182918616906370a0823190602401602060"
    "405180830381865afa1580156100a1573d5f803e3d5ffd5b505050506040513d601f19601f8201168201806040525"
    "08101906100c59190610200565b60405163a9059cbb60e01b81526001600160a01b038681166004830152602482018"
    "690529193509086169063a9059cbb906044016020604051808303815f875af1158015610115573d5f803e3d5ffd5b5"
    "05050506040513d601f19601f820116820180604052508101906101399190610217565b506040516370a0823160e01"
    "b81526001600160a01b0385811660048301528616906370a0823190602401602060405180830381865afa158015610"
    "17e573d5f803e3d5ffd5b505050506040513d601f19601f820116820180604052508101906101a29190610200565b90"
    "50935093915050565b80356001600160a01b03811681146101c2575f80fd5b919050565b5f805f6060848603121561"
    "01d9575f80fd5b6101e2846101ac565b92506101f0602085016101ac565b9150604084013590509250925092565b5f"
    "60208284031215610210575f80fd5b5051919050565b5f60208284031215610227575f80fd5b8151801515811461023"
    "6575f80fd5b939250505056fea2646970667358221220d37b50b26f8af2e1cf4805bba1c55f12493d93f492daafcabc"
    "ff9f4ad01b428d64736f6c63430008140033"
)

TEST_TAX_SELECTOR = bytes(Web3.keccak(text="testTax(address,address,uint256)"))[:4]

ERC20_BALANCE_ABI = [
    {"inputs": [{"type": "address"}], "name": "balanceOf", "outputs": [{"type": "uint256"}], "stateMutability": "view", "type": "function"},
]

DUMMY_RECIPIENT = Web3.to_checksum_address("0x000000000000000000000000000000000000dEaD")
TEST_FRACTION = float(os.environ.get("TAX_CHECK_TEST_FRACTION", "0.0001"))  # 0.01% of pool's balance
ZERO_TAX_THRESHOLD_PCT = float(os.environ.get("TAX_CHECK_ZERO_THRESHOLD_PCT", "0.5"))  # tolerance for rounding


def check_transfer_tax(token_address: str, pool_address: str) -> dict:
    """
    Returns:
      ok=True:  {"ok": True, "tax_pct": float, "is_zero_tax": bool}
      ok=False: {"ok": False, "reason": str}
    """
    token = Web3.to_checksum_address(token_address)
    pool = Web3.to_checksum_address(pool_address)

    try:
        contract = w3.eth.contract(address=token, abi=ERC20_BALANCE_ABI)
        pool_balance = contract.functions.balanceOf(pool).call()
    except Exception as e:
        return {"ok": False, "reason": f"could not read pool balance: {e}"}

    if pool_balance <= 0:
        return {"ok": False, "reason": "pool holds zero balance of this token"}

    test_amount = max(1, int(pool_balance * TEST_FRACTION))

    call_data = (
        TEST_TAX_SELECTOR
        + bytes(12) + bytes.fromhex(token[2:])
        + bytes(12) + bytes.fromhex(DUMMY_RECIPIENT[2:])
        + test_amount.to_bytes(32, "big")
    )

    try:
        result = w3.eth.call(
            {"to": pool, "data": call_data},
            state_override={pool: {"code": TAX_CHECKER_DEPLOYED_BYTECODE}},
        )
    except Exception as e:
        return {"ok": False, "reason": f"state-override call failed (RPC may not support stateOverride): {e}"}

    if len(result) < 64:
        return {"ok": False, "reason": f"unexpected return data length: {len(result)}"}

    before_ = int.from_bytes(result[0:32], "big")
    after_ = int.from_bytes(result[32:64], "big")
    received = after_ - before_

    if received < 0:
        return {"ok": False, "reason": "simulated balance decreased -- unexpected token behavior"}

    tax_pct = max(0.0, (1 - (received / test_amount)) * 100) if test_amount > 0 else 0.0

    return {"ok": True, "tax_pct": tax_pct, "is_zero_tax": tax_pct <= ZERO_TAX_THRESHOLD_PCT}
