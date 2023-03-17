import * as secp256k1 from './secp256k1.js'
import * as keccak256 from './keccak256.js'

/**
 * Derives an Ethereum address from a secp256k1 public key point.
 *
 * @param publicKey A secp256k1 public key point.
 * @returns An Ethereum address, as a 20-byte Uint8Array.
 */
export async function publicKeyToAddress(publicKey: secp256k1.AffinePoint): Promise<bigint> {
	const encodedPublicKey = secp256k1.encodePoint(publicKey)
	const hashedPublicKey = await keccak256.hash(encodedPublicKey.subarray(1, 65))
	return hashedPublicKey & 0xffffffffffffffffffffffffffffffffffffffffn
}

/**
 * Turns an Ethereum address into a string, including lower/upper case for checksum information encoding.
 * @param address An Ethereum address as a bigint.
 * @returns An Ethereum address as a checksummed string.
 */
export async function addressToChecksummedString(address: bigint): Promise<string> {
	const addresString = address.toString(16).padStart(40, '0')
	const addressHash = await keccak256.hash(new TextEncoder().encode(addresString))
	let result = ''
	for (let i = 0; i < addresString.length; ++i) {
		const character = addresString[i]
		const isLetter = /[a-fA-F]/.test(character)
		const checksumBit = addressHash & (2n**(255n - 4n * BigInt(i)))
		if (isLetter && checksumBit) result += character.toUpperCase()
		else result += character.toLowerCase()
	}
	return result
}

/**
 * Validates that a hex string address is valid per checksum check.
 * @param addressString Address as a hex string, with checksum casing encoded in it.
 * @returns True if the address is valid, false otherwise.
 */
export async function validateAddressChecksum(addressString: string): Promise<boolean> {
	addressString = addressString.startsWith('0x') ? addressString : `0x${addressString}`
	if (!/0x[a-fA-F0-9]{40}/.test(addressString)) return false
	const addressBigint = BigInt(addressString)
	const checksummedAddress = await addressToChecksummedString(addressBigint)
	return (checksummedAddress === addressString.slice(2))
}

/**
 * Signs the keccak256 hash of `message` using `privateKey`.
 * @param privateKey The private key used to sign `message` with.
 * @param message The message to be signed.  This can be either a string, which will be UTF-8 encoded, or a byte array.
 * @returns The signature of `message` signed by `privateKey`.
 */
export async function signRaw(privateKey: bigint, message: string | Uint8Array): Promise<secp256k1.Signature> {
	message = (typeof message === 'string') ? new TextEncoder().encode(message) : message
	const hashedMessage = await keccak256.hash(message)
	const signature = await secp256k1.sign(privateKey, hashedMessage)
	return signature
}

/**
 * Many signing tools in the Ethereum ecosystem prefix all signed messages with a magic string before signing.  This applies that prefix and returns the message that most tools will _actually_ sign.  This can be passed to `signRaw` for actual signing.
 * @param message The message to prep for signing.  This can be either a string, which will be UTF-8 encoded, or a byte array.
 * @returns A message that can be signed by `signRaw` and will be correctly verified by various Ethereum ecosystem tools.
 */
export function mutateMessageForSigning(message: string | Uint8Array): Uint8Array {
	message = (typeof message === 'string') ? new TextEncoder().encode(message) : message
	const messagePrefix = new TextEncoder().encode(`\x19Ethereum Signed Message:\n${message.length.toString(10)}`)
	return new Uint8Array([...messagePrefix, ...message])
}

/**
 * Signs the keccak256 hash of a prefixed version of {message}.  Many signing tools in the Ethereum ecosystem prefix all signed messages with a magic prefix before signing.
 *
 * The magic prefix is `\x19Ethereum Signed Message:\n${messageLength}` where `messageLength` is the base-10 ASCII encoded length of the [UTF-8 encoded (if message is a string)] message
 * @param privateKey The private key used to sign `message` with.
 * @param message The message to be signed.  This can be either a string, which will be UTF-8 encoded, or a byte array.
 * @returns The signature of the mutated `message` signed by `privateKey`.
 */
export async function mutateAndSign(privateKey: bigint, message: string | Uint8Array): Promise<secp256k1.Signature> {
	const bytesToSign = mutateMessageForSigning(message)
	return signRaw(privateKey, bytesToSign)
}

/**
 * Converts a Solidity canonical function signature (e.g., `transfer(address,uint256)`) into its function selector.  See https://solidity.readthedocs.io/en/latest/abi-spec.html#function-selector for details.
 * @param functionSignature The canonical expression of the Solidity function signature.  See https://solidity.readthedocs.io/en/latest/abi-spec.html#function-selector for details on constructing this appropriately.
 */
export async function functionSignatureToSelector(functionSignature: string): Promise<number> {
	const functionSignatureBytes = new TextEncoder().encode(functionSignature)
	const hash = await keccak256.hash(functionSignatureBytes)
	return Number(hash >> 224n)
}
