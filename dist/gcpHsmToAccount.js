"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.gcpHsmToAccount = gcpHsmToAccount;
const kms_1 = require("@google-cloud/kms");
const asn1 = __importStar(require("asn1js"));
const accounts_1 = require("viem/accounts");
const viem_1 = require("viem");
const secp256k1_1 = require("@noble/curves/secp256k1");
// Including 0x prefix
const UNCOMPRESSED_PUBLIC_KEY_HEX_LENGTH = 132; // 2 * 66
async function getPublicKey(kmsClient, hsmKeyVersion) {
    const [pk] = await kmsClient.getPublicKey({ name: hsmKeyVersion });
    if (!pk.pem) {
        throw new Error('PublicKey pem is not defined');
    }
    const derEncodedPk = pemToDer(pk.pem);
    return publicKeyFromDer(derEncodedPk);
}
/**
 * Converts key from PEM to DER encoding.
 *
 * DER (Distinguished Encoding Rules) is a binary encoding for X.509 certificates and private keys.
 * Unlike PEM, DER-encoded files do not contain plain text statements such as -----BEGIN CERTIFICATE-----
 *
 * https://www.ssl.com/guide/pem-der-crt-and-cer-x-509-encodings-and-conversions/#:~:text=DER%20(Distinguished%20Encoding%20Rules)%20is,commonly%20seen%20in%20Java%20contexts.
 */
function pemToDer(pem) {
    const base64 = pem.split('\n').slice(1, -2).join('').trim();
    return Buffer.from(base64, 'base64');
}
function publicKeyFromDer(bytes) {
    // DER is a subset of BER (Basic Encoding Rules)
    const { result } = asn1.fromBER(bytes);
    const values = result.valueBlock.value;
    if (values.length < 2) {
        throw new Error('Cannot get public key from ASN.1: invalid sequence');
    }
    const value = values[1];
    return (0, viem_1.toHex)(value.valueBlock.valueHexView);
}
async function signWithKms(kmsClient, hsmKeyVersion, hash) {
    const [signResponse] = await kmsClient.asymmetricSign({
        name: hsmKeyVersion,
        digest: {
            sha256: hash,
        },
    });
    // Return normalized signature
    // > All transaction signatures whose s-value is greater than secp256k1n/2 are now considered invalid.
    // See https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2.md
    return secp256k1_1.secp256k1.Signature.fromDER(signResponse.signature).normalizeS();
}
/**
 * Attempts each recovery key to find a match
 */
async function getRecoveredSignature(signature, publicKey, hash) {
    for (let i = 0; i < 4; i++) {
        const recoveredSig = signature.addRecoveryBit(i);
        const compressed = publicKey.length < UNCOMPRESSED_PUBLIC_KEY_HEX_LENGTH;
        const recoveredPublicKey = `0x${recoveredSig.recoverPublicKey(hash).toHex(compressed)}`;
        if (publicKey === recoveredPublicKey) {
            return recoveredSig;
        }
    }
    throw new Error('Unable to generate recovery key from signature.');
}
async function sign(kmsClient, hsmKeyVersion, publicKey, msgHash) {
    const hash = (0, viem_1.hexToBytes)(msgHash);
    const signature = await signWithKms(kmsClient, hsmKeyVersion, hash);
    const { r, s, recovery } = await getRecoveredSignature(signature, publicKey, hash);
    return {
        r: (0, viem_1.toHex)(r),
        s: (0, viem_1.toHex)(s),
        v: BigInt(recovery) + 27n,
        yParity: recovery,
    };
}
function getClientCredentials() {
    try {
        // handle if process is not available i.e. browser
        return process.env.GOOGLE_APPLICATION_CREDENTIAL_EMAIL &&
            process.env.GOOGLE_APPLICATION_CREDENTIAL_PRIVATE_KEY
            ? {
                credentials: {
                    client_email: process.env.GOOGLE_APPLICATION_CREDENTIAL_EMAIL,
                    private_key: process.env.GOOGLE_APPLICATION_CREDENTIAL_PRIVATE_KEY.replace(/\\n/gm, '\n'),
                },
            }
            : {};
    }
    catch {
        return {};
    }
}
async function gcpHsmToAccount({ hsmKeyVersion, kmsClient: kmsClient_, }) {
    const kmsClient = kmsClient_ ?? new kms_1.KeyManagementServiceClient(getClientCredentials());
    const publicKey = await getPublicKey(kmsClient, hsmKeyVersion);
    const address = (0, accounts_1.publicKeyToAddress)(publicKey);
    const account = (0, accounts_1.toAccount)({
        address,
        async signMessage({ message }) {
            const signature = await sign(kmsClient, hsmKeyVersion, publicKey, (0, viem_1.hashMessage)(message));
            return (0, viem_1.signatureToHex)(signature);
        },
        async sign({ hash }) {
            const signature = await sign(kmsClient, hsmKeyVersion, publicKey, hash);
            return (0, viem_1.signatureToHex)(signature);
        },
        async signTransaction(transaction, { serializer = viem_1.serializeTransaction } = {}) {
            // Copied from https://github.com/wevm/viem/blob/e6c47807f32d14ded53c40831177ee80c5a47a10/src/accounts/utils/signTransaction.ts
            // TODO: would be nice for this to be done before in viem
            // so custom Account implementations don't have to worry about it
            const signableTransaction = (() => {
                // For EIP-4844 Transactions, we want to sign the transaction payload body (tx_payload_body) without the sidecars (ie. without the network wrapper).
                // See: https://github.com/ethereum/EIPs/blob/e00f4daa66bd56e2dbd5f1d36d09fd613811a48b/EIPS/eip-4844.md#networking
                if (transaction.type === 'eip4844')
                    return {
                        ...transaction,
                        sidecars: false,
                    };
                return transaction;
            })();
            const hash = (0, viem_1.keccak256)(serializer(signableTransaction));
            const signature = await sign(kmsClient, hsmKeyVersion, publicKey, hash);
            return serializer(transaction, signature);
        },
        async signTypedData(typedData) {
            const signature = await sign(kmsClient, hsmKeyVersion, publicKey, (0, viem_1.hashTypedData)(typedData));
            return (0, viem_1.signatureToHex)(signature);
        },
    });
    return {
        ...account,
        publicKey,
        source: 'gcpHsm',
    };
}
//# sourceMappingURL=gcpHsmToAccount.js.map