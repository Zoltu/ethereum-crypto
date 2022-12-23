import { bigintToBytes, modularMultiplicitiveInverse, bytesToBigint, modularTryFindPerfectSquareRoot } from './utilities'

export interface AffinePoint {
	/** [0, 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f) */
	x: bigint
	/** [0, 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f) */
	y: bigint
}

export interface JacobianPoint {
	/** [0, 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f) */
	x: bigint
	/** [0, 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f) */
	y: bigint
	/** [0, 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f) */
	z: bigint
}

export interface Signature {
	/** [0, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141) */
	r: bigint
	/** [0, 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0) */
	s: bigint
	recoveryParameter: 0|1
}

export const fieldModulus = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn as const
const a = 0n
const b = 7n
export const basePoint: JacobianPoint = {
	x: 55066263022277343669578718895168534326250603453777594175500187360389116729240n,
	y: 32670510020758816978083085130507043184471273380659243275938904335757337482424n,
	z: 1n,
} as const
export const basePointOrder = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n as const
// const h = 1n

/**
 * Generates a random valid private key for usage is secp256k1 signing.
 */
export async function generatePrivateKey(): Promise<bigint> {
	let result = 2n**256n
	while (result >= basePointOrder || result <= 0) {
		result = bytesToBigint(crypto.getRandomValues(new Uint8Array(32)))
	}
	validatePrivateKey(result)
	return result
}

/**
 * Derives the public key that corresponds to {privateKey}.
 * @param privateKey A valid secp256k1 private key.  Usually a random number. Must be in the range (0, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141).
 */
export async function privateKeyToPublicKey(privateKey: bigint): Promise<JacobianPoint & AffinePoint> {
	privateKey = (typeof privateKey === 'bigint') ? privateKey : bytesToBigint(privateKey)
	validatePrivateKey(privateKey)
	// we convert to affine and back to jacobian because that will result in getting a public key out that is compatible with both jacobian or affine systems, while the original jacobian key may only be compatible with jacobian processing
	const jacobianPublicKey = pointMultiply(basePoint, privateKey)
	const affinePublicKey = jacobianToAffine(jacobianPublicKey)
	return affineToJacobian(affinePublicKey)
}

export function encodePoint(point: JacobianPoint | AffinePoint): Uint8Array & { length: 65 } {
	const affinePoint = ('z' in point) ? jacobianToAffine(point) : point
	const result = [4]
	for (let i = 0n; i < 32n; ++i) {
		result.push(Number((affinePoint.x >> 248n - 8n * i) & 0xffn))
	}
	for (let i = 0n; i < 32n; ++i) {
		result.push(Number((affinePoint.y >> 248n - 8n * i) & 0xffn))
	}
	return new Uint8Array(result) as Uint8Array & { length: 65 }
}

export function encodePointCompressed(point: JacobianPoint | AffinePoint): Uint8Array & {length:33} {
	const affinePoint = ('z' in point) ? jacobianToAffine(point) : point
	return new Uint8Array([(affinePoint.y % 2n) ? 0x03 : 0x02, ...bigintToBytes(affinePoint.x, 32)]) as Uint8Array & {length:33}
}

export function decodePoint(encoded: ArrayLike<number> & { length: 65 }): JacobianPoint & AffinePoint {
	if (encoded[0] !== 4) throw new Error(`This is not an encoded point.  Perhaps you have a compressed point?\n${encoded}`)
	let x = 0n
	for (let i = 1; i <= 32; ++i) {
		const shift = ((32n - BigInt(i)) * 8n)
		x |= BigInt(encoded[i]) << shift
	}
	let y = 0n
	for (let i = 1; i <= 32; ++i) {
		const shift = ((32n - BigInt(i)) * 8n)
		y |= BigInt(encoded[i + 32]) << shift
	}
	return affineToJacobian({ x, y })
}

export function decompressPoint(x: bigint, recoveryParameter: 0|1) {
	const maybeY= modularTryFindPerfectSquareRoot(normalizeScalarInField(x**3n + a*x + b), fieldModulus)
	if (maybeY === undefined) throw new Error(`Invalid signature: not a valid point on curve`)
	const y = (recoveryParameter === Number(maybeY[0] % 2n)) ? maybeY[0] : maybeY[1]
	return y
}

/**
 * Sign {messageHash} with {privateKey}.  {messageHash} is usually the output of a hashing function (e.g., keccak256) run against some data that you wish to sign.
 * @param privateKey The private key you wish to sign with.  Usually a randomly generated 256-bit number.  Note that the valid range of values is actually constrained to (0, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)
 * @param messageHash The 256-bit number you wish to sign.  Usually this is the output of a hashing function like keccak256. [0, 2**256)
 */
export async function sign(privateKey: bigint, messageHash: bigint): Promise<Signature> {
	validateMessageHash(messageHash)
	validatePrivateKey(privateKey)
	async function signInternal(noncesToSkip: number): Promise<Signature> {
		const nonce = await generateDeterministicSigningNonce(privateKey, messageHash, noncesToSkip)
		const point = jacobianToAffine(pointMultiply(basePoint, nonce))
		// ethereum specific case, in bitcoin `r = point.x % basePointOrder` and point.x being larger than basePointOrder is encoded as part of the `recoveryParameter`.
		if (point.x >= basePointOrder) return await signInternal(noncesToSkip + 1)
		const r = point.x
		const maybeS = modularMultiplicitiveInverse(nonce, basePointOrder) * (messageHash + r * privateKey) % basePointOrder
		// if there are multiple valid values of s, prefer the smaller one
		const s = maybeS < basePointOrder / 2n ? maybeS : basePointOrder - maybeS
		// if we ended up using a different `s` then we calculated, then invert the recoveryParameter
		const recoveryParameter = maybeS < basePointOrder / 2n
			? point.y % 2n ? 1 : 0 as const
			: point.y % 2n ? 0 : 1 as const
		return { r, s, recoveryParameter }
	}
	return signInternal(0)
}

/**
 * Verify that {signature} is the result of signing {messageHash} with the private key corresponding to {publicKey}.
 * @param publicKey The secp256k1 public key cooresponding to the private key that signed messageHash.
 * @param messageHash The 256-bit number that was signed.  Usually this is the output of a hashing function like keccak256. [0, 2**256)
 * @param signature The signature output from signing with the private key cooresponding to {publicKey} parameter
 */
export async function verify(publicKey: JacobianPoint | AffinePoint, messageHash: bigint, signature: Omit<Signature, 'recoveryParameter'>): Promise<boolean> {
	validateMessageHash(messageHash)
	const affinePublicKey = ('z' in publicKey) ? jacobianToAffine(publicKey) : publicKey
	const jacobianPublicKey = ('z' in publicKey) ? publicKey : affineToJacobian(publicKey)
	// verify it isn't the point at infinity
	if (isAtInfinity(jacobianPublicKey)) return false
	// verify the point is on the curve y^2 = x^3 + 7 (the secp256k1 curve)
	if ((affinePublicKey.x ** 3n + 7n) % fieldModulus !== (affinePublicKey.y ** 2n) % fieldModulus) return false
	// verify that the base point order times the point is the point at infinity
	const expectedInfinitePoint = pointMultiply(jacobianPublicKey, basePointOrder)
	if (!isAtInfinity(expectedInfinitePoint)) return false
	// verify r is in the proper range
	const signatureR = signature.r
	if (signatureR <= 0) return false
	if (signatureR >= basePointOrder) return false
	// verify s is in the proper range
	const signatureS = signature.s
	if (signatureS <= 0) return false
	if (signatureS >= basePointOrder) return false

	// verify the signature
	const inverseS = modularMultiplicitiveInverse(signatureS, basePointOrder)
	const u1 = messageHash * inverseS % basePointOrder
	const u2 = signatureR * inverseS % basePointOrder
	const calculatedPoint = pointAdd(pointMultiply(basePoint, u1), pointMultiply(jacobianPublicKey, u2))
	if (isAtInfinity(calculatedPoint)) return false
	if (jacobianToAffine(calculatedPoint).x !== signatureR) return false

	// all of the checks for validity passed, thus the signature is valid
	return true
}

/**
 * Recover the public key associated with the private key that was used to sign {messageHash} and resulted in {signature}.
 * @param messageHash The hash of the message that was signed.
 * @param signature The signature of the message that was signed.
 */
export async function recover(messageHash: bigint, signature: Signature): Promise<JacobianPoint & AffinePoint> {
	if (signature.r <= 0 || signature.r > basePointOrder) throw new Error(`Invalid signature: 'r' (${signature.s}) is out of range`)
	if (signature.s <= 0 || signature.s > basePointOrder) throw new Error(`Invalid signature: 's' (${signature.s}) is out of range`)
	const x = normalizeScalarInField(signature.r + BigInt(signature.recoveryParameter) * fieldModulus)
	if (x >= fieldModulus) throw new Error(`Invalid signature: 'r' (${signature.r}) is out of range`)
	const y = decompressPoint(x, signature.recoveryParameter)
	const rInverse = modularMultiplicitiveInverse(signature.r, basePointOrder)
	const sTimesRInverse = rInverse * signature.s % basePointOrder
	const negativeMessageTimesRInverse = rInverse * (basePointOrder - messageHash) % basePointOrder
	const result = pointAdd(pointMultiply(basePoint, negativeMessageTimesRInverse), pointMultiply(affineToJacobian({ x, y }), sTimesRInverse))
	// we convert to affine and back to jacobian because that will result in getting a public key out that is compatible with both jacobian or affine systems, while the original jacobian key may only be compatible with jacobian stuff
	return affineToJacobian(jacobianToAffine(normalizePointInField(result)))
}

async function generateDeterministicSigningNonce(privateKey: bigint, messageHash: bigint, numberToSkip: number): Promise<bigint> {
	const privateKeyBytes = bigintToBytes(privateKey, 32)
	const messageHashBytes = bigintToBytes(messageHash, 32)
	let v = new Uint8Array(32).fill(1) as Uint8Array & {length:32}
	let k = new Uint8Array(32).fill(0) as Uint8Array & {length:32}
	k = await hmac(k, [...v, 0, ...privateKeyBytes, ...messageHashBytes])
	v = await hmac(k, v)
	k = await hmac(k, [...v, 1,  ...privateKeyBytes, ...messageHashBytes])
	v = await hmac(k, v)

	let foundCount = 0
	while (true) {
		v = await hmac(k, v)
		const nonce = bytesToBigint(v)
		if (nonce >= 1n && nonce < basePointOrder) {
			foundCount += 1
			if (foundCount > numberToSkip) return nonce
		}
		k = await hmac(k, [...v, 0])
		v = await hmac(k, v)
	}
}

async function hmac(key: Uint8Array & {length:32}, data: Iterable<number>): Promise<Uint8Array & {length:32}> {
	const cryptoKey = await crypto.subtle.importKey('raw', key, {name:'HMAC', hash:'SHA-256'}, false, ['sign'])
	const signature = await crypto.subtle.sign('HMAC', cryptoKey, new Uint8Array(data))
	return new Uint8Array(signature) as Uint8Array & {length:32}
}

function validatePrivateKey(privateKey: bigint): void {
	if (privateKey < 1) throw new Error(`Illegal private key.  Must be in range [1, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140]`)
	if (privateKey >= basePointOrder) throw new Error(`Illegal private key.  Must be in range [1, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)`)
}

function validateMessageHash(messageHash: bigint): void {
	if (messageHash < 0) throw new Error(`Message hash must be a positive number.`)
	if (messageHash >= 2n ** 256n) throw new Error(`Message hash is too big.  It must be a 256-bit number.`)
}

function pointMultiply(point: JacobianPoint, scalar: bigint): JacobianPoint {
	// https://en.wikipedia.org/wiki/Exponentiation_by_squaring (aka: double-and-add)
	let result: JacobianPoint = {x: 1n, y: 1n, z: 0n}
	if (scalar === 0n) return {x: 0n, y: 0n, z: 0n}
	if (isAtInfinity(point)) return {x: 0n, y: 0n, z: 0n}
	for (let i = 0n; i < 256n; ++i) {
		result = pointDouble(result)
		const bit = !!((scalar >> 255n - i) & 0b1n)
		if (bit) result = pointAdd(result, point)
	}
	return normalizePointInField(result)
}

function pointAdd(first: JacobianPoint, second: JacobianPoint): JacobianPoint {
	// http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-add-2007-bl
	if (isAtInfinity(first)) return second
	if (isAtInfinity(second)) return first

	const firstZSquared = first.z * first.z % fieldModulus
	const secondZSquared = second.z * second.z % fieldModulus
	const u1 = first.x * secondZSquared % fieldModulus
	const u2 = second.x * firstZSquared % fieldModulus
	const s1 = first.y * second.z * secondZSquared % fieldModulus
	const s2 = second.y * first.z * firstZSquared % fieldModulus
	if (u1 === u2) {
		if (s1 === s2) return pointDouble(first)
		else return { x: 1n, y: 1n, z: 0n }
	}
	const h = (u2 - u1) % fieldModulus
	const i = (2n * h)**2n % fieldModulus
	const j = h * i % fieldModulus
	const r = 2n * (s2 - s1) % fieldModulus
	const v = u1 * i % fieldModulus
	const x = (r * r - j - 2n * v) % fieldModulus
	const y = (r * (v - x) - 2n * s1 * j) % fieldModulus
	const z = ((first.z + second.z)**2n - firstZSquared - secondZSquared) * h % fieldModulus
	return { x, y, z }
}

function pointDouble(point: JacobianPoint): JacobianPoint {
	// http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l
	const xSquared = point.x * point.x % fieldModulus
	const ySquared = point.y * point.y % fieldModulus
	const yQuarted = ySquared * ySquared % fieldModulus
	const d = 2n * ((point.x + ySquared)**2n - xSquared - yQuarted) % fieldModulus
	const e = 3n * xSquared % fieldModulus
	const f = e**2n % fieldModulus
	const x = (f - 2n * d) % fieldModulus
	const y = (e * (d - x) - 8n * yQuarted) % fieldModulus
	const z = 2n * point.y * point.z % fieldModulus
	return { x, y, z }
}

function isAtInfinity(point: JacobianPoint | AffinePoint): boolean {
	if ('z' in point) {
		if (point.z !== 0n) return false
		if (point.x ** 3n % fieldModulus !== point.y ** 2n % fieldModulus) return false
		return true
	} else {
		if (point.x !== 0n) return false
		if (point.y !== 0n) return false
		return true
	}
}

function affineToJacobian(affine: AffinePoint): JacobianPoint {
	if (isAtInfinity(affine)) return { x: 1n, y: 1n, z: 0n }
	return {
		x: affine.x,
		y: affine.y,
		z: 1n
	}
}

function jacobianToAffine(jacobian: JacobianPoint): AffinePoint {
	if (isAtInfinity(jacobian)) return { x: 0n, y: 0n }
	if (jacobian.z === 1n) return { x: jacobian.x, y: jacobian.y }
	const zInverse = modularMultiplicitiveInverse(jacobian.z, fieldModulus)
	return {
		x: jacobian.x * zInverse ** 2n % fieldModulus,
		y: jacobian.y * zInverse ** 3n % fieldModulus,
	}
}

function normalizePointInField(point: JacobianPoint): JacobianPoint
function normalizePointInField(point: AffinePoint): AffinePoint
function normalizePointInField(point: JacobianPoint | AffinePoint): JacobianPoint | AffinePoint {
	const x = normalizeScalarInField(point.x)
	const y = normalizeScalarInField(point.y)
	if ('z' in point) {
		const z = normalizeScalarInField(point.z)
		return { x, y, z }
	} else {
		return { x, y }
	}
}

function normalizeScalarInField(value: bigint): bigint {
	if (value >= fieldModulus) return value % fieldModulus
	if (value < 0n) return normalizeScalarInField(value + fieldModulus)
	return value
}

/**
 * These are here for reference.  They are nearly the most simple implementation of secp256k1 point add/point multiply functions.  The only optimization they have is that they use double and add for multiplication rather than adding a number 2**256 times in a loop (which is impossible on modern computers).  While the code is not used since using Jacobian coordinates are about 30x faster, I'm leaving it in here for reference in case some future reader wants to understand what is happening under the hood a litle better.
 */

// function pointAdd(first: AffinePoint, second: AffinePoint): AffinePoint {
// 	// if one of the points is the infinite point, then return the other
// 	if (first.x === 0n && first.y === 0n) return second
// 	if (second.x === 0n && second.y === 0n) return first
// 	// if both points are the same, we can use the doubling formula (adding a point to itself doesn't work)
// 	if (first.x === second.x && first.y === second.y) return pointDouble(first)
// 	// if one point is the negation of the other, then return the infinite point
// 	if (first.x === second.x && first.y === first.y * -1n + fieldModulus) return { x:0n, y:0n }
// 	// if x is the same but y is different then it means we are adding a point to its negation, in which case the result is the point at infinity
// 	if (first.x === second.x) return {x:0n, y:0n}
// 	const slope = div(sub(second.y, first.y), sub(second.x, first.x))
// 	const resultX = sub(sub(slope * slope, first.x), second.x)
// 	const resultY = sub(slope * sub(first.x, resultX), first.y)
// 	return { x: resultX % fieldModulus, y: resultY % fieldModulus }
// }

// function pointDouble(point: AffinePoint): AffinePoint {
// 	if (point.x === 0n && point.y === 0n) return point
// 	if (point.y + point.y === 0n) return {x:0n, y:0n}
// 	const slope = div(3n * point.x * point.x, 2n * point.y)
// 	const resultX = sub(sub(slope * slope, point.x), point.x)
// 	const resultY = sub(slope * sub(point.x, resultX), point.y)
// 	return { x: resultX % fieldModulus, y: resultY % fieldModulus }
// }

// function sub(minuend: bigint, subtrahend: bigint): bigint {
// 	return modularSubtract(minuend, subtrahend, fieldModulus)
// }

// function div(dividend: bigint, divisor: bigint): bigint {
// 	return modularDivide(dividend, divisor, fieldModulus)
// }
