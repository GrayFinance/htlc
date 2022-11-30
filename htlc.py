from bitcoin.core.script import CScript, OP_DUP, OP_EQUALVERIFY, OP_HASH160, OP_IF, OP_ELSE, OP_CHECKLOCKTIMEVERIFY
from bitcoin.core.script import OP_0, OP_DROP, OP_ENDIF, OP_CHECKSIG, SignatureHash, SIGVERSION_WITNESS_V0, SIGHASH_ALL
from bitcoin.wallet import P2WSHBitcoinAddress, CBitcoinAddress, CBitcoinSecret
from bitcoin.core import Hash160, lx, b2x, CScriptWitness, CMutableTxIn, COutPoint, CMutableTxOut, CMutableTransaction, CTxWitness, CTxInWitness
from bitcoin import SelectParams

import hashlib

class HTLC:

    def __init__(self, network: str = "mainnet"):
        SelectParams(network)
    
    def create_witness_script(self, image: bytes, broker: bytes, customer: bytes, locktime: int) -> bytes:
        image = hashlib.new("ripemd160", image).digest()
        return CScript([
            OP_IF,
                OP_HASH160, image, OP_EQUALVERIFY, OP_DUP, OP_HASH160, Hash160(customer),
            OP_ELSE,
                locktime, OP_CHECKLOCKTIMEVERIFY, OP_DROP, OP_DUP, OP_HASH160, Hash160(broker),
            OP_ENDIF,
            OP_EQUALVERIFY,
            OP_CHECKSIG,
        ])
    
    def create_p2wsh_address(self, script: bytes) -> str:
        return P2WSHBitcoinAddress.from_scriptPubKey(CScript([OP_0,hashlib.sha256(script).digest()])).__str__()
    
class Tx:

    def __init__(self, network: str = "mainnet"):
        SelectParams(network)
    
    def create_signed_tx(self, key: str, script: str, anchor: str, address: str, value: int, secret=None, locktime=None, no_signature=False) -> str:
        key = CBitcoinSecret(key)
        
        # Separate data from the 
        # anchor transaction.
        anchor = anchor.split(":")
        anchor[0] = lx(anchor[0])
        anchor[1] = int(anchor[1])
        anchor[2] = int(anchor[2])
        
        script = CScript.fromhex(script)
        
        txvin = CMutableTxIn(COutPoint(anchor[0], anchor[1]))
        txout = CMutableTxOut(value, CBitcoinAddress(address).to_scriptPubKey())
        if (locktime):
            txvin.nSequence = 0

        tx = CMutableTransaction([txvin], [txout])
        if (locktime):
            tx.nLockTime = locktime

        signature_hash = SignatureHash(
            script=script,
            txTo=tx,
            inIdx=0,
            hashtype=SIGHASH_ALL,
            amount=anchor[-1],
            sigversion=SIGVERSION_WITNESS_V0,
        )
        if (no_signature == True):
            return b2x(tx.serialize())
        else:
            signature = key.sign(signature_hash) + bytes([SIGHASH_ALL])
            witness = [signature, key.pub]
            if (secret):
                witness.extend([secret, b"\x01", script])
            else:
                witness.extend([b"", script])
            
            witness = CScriptWitness(witness)
            tx.wit = CTxWitness([CTxInWitness(witness)])
            return b2x(tx.serialize())