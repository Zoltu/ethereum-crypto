import { bigintToBytes, bytesToBigint } from './utilities';
import * as secp256k1 from './secp256k1';

const masterSeed = new TextEncoder().encode('Bitcoin seed')

/**
 * @param seed The seed value to use, such as that returned by `mnemonic.toSeed()`. If a bigint is supplied, it is converted to a 64-byte array (big endian, left padded with 0)
 * @param derivationPath The BIP 32 derivation path to use when deriving the key from the seed.  If not supplied then `m/44'/60'/0'/0/0` is used.
 * @returns A 64-bit private key valid for usage in secp256k1.
 */
export async function privateKeyFromSeed(seed: Uint8Array | bigint, derivationPath?: string): Promise<bigint> {
	if (typeof seed === 'bigint') seed = bigintToBytes(seed, 64)
	if (derivationPath === undefined) derivationPath = `m/44'/60'/0'/0/0`

	const hmacKey = await crypto.subtle.importKey('raw', masterSeed, {name:'HMAC', hash:'SHA-512'}, true, ['sign'])
	const masterSeedHmac = new Uint8Array(await crypto.subtle.sign('HMAC', hmacKey, seed))
	const masterKey = bytesToBigint(masterSeedHmac.subarray(0, 32))
	if (masterKey === 0n) throw new Error(`Invalid seed.`)
	if (masterKey >= secp256k1.basePointOrder) throw new Error(`Invalid seed.`)
	const masterChainCode = masterSeedHmac.subarray(32, 64) as Uint8Array & {length:32}
	const chain = decodeDerivationPath(derivationPath)
	let currentKeyCodePair: KeyChainPair = { key: masterKey, chainCode: masterChainCode }
	for (const link of chain) {
		currentKeyCodePair = await deriveChild(currentKeyCodePair, link.index, link.hardened)
	}

	return currentKeyCodePair.key
}

async function deriveChild(parent: KeyChainPair, index: number, hardened: boolean): Promise<KeyChainPair> {
	function hardenedHmacData(): Uint8Array {
		const keyBytes = bigintToBytes(parent.key, 32)
		return new Uint8Array([0x00, ...keyBytes, ...indexBytes])
	}
	async function normalHmacData(): Promise<Uint8Array> {
		const publicKey = await secp256k1.privateKeyToPublicKey(parent.key)
		const compressedPublicKey = secp256k1.encodePointCompressed(publicKey)
		return new Uint8Array([...compressedPublicKey, ...indexBytes])
	}
	const indexBytes = bigintToBytes(BigInt(index + (hardened ? 2**31 : 0)), 4)
	const hmacData = hardened ? hardenedHmacData() : await normalHmacData()
	const hmacKey = await crypto.subtle.importKey('raw', parent.chainCode, {name:'HMAC', hash:'SHA-512', length: 256}, true, ['sign'])
	const hmac = new Uint8Array(await crypto.subtle.sign('HMAC', hmacKey, hmacData))
	const childKey = (bytesToBigint(hmac.subarray(0, 32)) + parent.key) % secp256k1.basePointOrder
	const childChainCode = hmac.subarray(32, 64) as Uint8Array & {length:32}
	if (childKey === 0n) return await deriveChild(parent, index + 1, hardened)
	if (childKey >= secp256k1.basePointOrder) return await deriveChild(parent, index + 1, hardened)

	return { key: childKey, chainCode: childChainCode }
}

function decodeDerivationPath(derivationPath: string): Array<{hardened:boolean,index:number}> {
	if (!/^m(?:\/\d+'?)*$/g.test(derivationPath)) throw new Error(`Invalid derivation path ${derivationPath}`);

	const result: Array<{hardened:boolean,index:number}> = []
	const regularExpression = /\/(\d+'?)/g
	let match = null
	while ((match = regularExpression.exec(derivationPath)) !== null) {
		const hardened = match[1].lastIndexOf(`'`) !== -1
		const index = Number.parseInt(hardened ? match[1].slice(0, -1) : match[1])
		result.push({hardened, index})
	}

	return result
}

interface KeyChainPair {
	key: bigint
	chainCode: Uint8Array
}
