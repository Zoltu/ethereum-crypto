export function validateByteArray(message: Iterable<number>): void {
	for (const maybeByte of message) {
		if (maybeByte >= 2**8) throw new Error(`Expected a byte array but received an array with elements larger than 2**8`)
		if (maybeByte < 0) throw new Error(`Expected byte array but received an array with negative elements`)
	}
}

export function chunkArray<T, L extends number>(array: Array<T>, chunkSize: L): Array<Array<T> & {length:L}> {
	const chunks = new Array<Array<T> & {length:L}>()
	for (let i = 0; i < array.length; i += chunkSize) {
		const chunk = array.slice(i, i + chunkSize) as Array<T> & {length:L}
		chunks.push(chunk)
	}
	return chunks
}

export function bytesToBigint<L extends number>(array: ArrayLike<number> & {length:L}): bigint {
	let result = 0n
	for (let i = 0; i < array.length; ++i) {
		const shiftAmount = BigInt((array.length - 1 - i) * 8)
		const byte = BigInt(array[i])
		result |= byte << shiftAmount
	}
	return result
}

export function bigintToBytes<L extends number>(value: bigint, numberOfBytes: L): Uint8Array & {length:L} {
	if (value >= 2n**BigInt(numberOfBytes * 8)) throw new Error(`Cannot encode ${value} in ${numberOfBytes} bytes.`)
	if (value < 0) throw new Error(`This function cannot encode a negative number (${value}).`)
	const result = new Uint8Array(numberOfBytes)
	for (let i = 0; i < numberOfBytes; ++i) {
		const shiftAmount = BigInt((numberOfBytes - 1 - i) * 8)
		const byte = Number((value >> shiftAmount) & 0xffn)
		result[i] = byte
	}
	return result as Uint8Array & {length:L}
}

export function rightCircularShift64(value: bigint, bits: bigint): bigint {
	value = value % 2n**64n
	bits = bits % 64n
	const newSignificantBits = (value << (64n - bits)) % 2n**64n
	const newInsignificantBits = value >> bits
	return newSignificantBits | newInsignificantBits
}

export function leftCircularShift64(value: bigint, bits: bigint): bigint {
	value = value % 2n**64n
	bits = bits % 64n
	const newSignificantBits = (value << bits) % 2n**64n
	const newInsignificantBits = value >> (64n - bits)
	return newSignificantBits | newInsignificantBits
}

export function modularSubtract(minuend: bigint, subtrahend: bigint, fieldModulus: bigint): bigint {
	const difference = (minuend - subtrahend) % fieldModulus
	return (difference >= 0) ? difference : difference + fieldModulus
}

export function modularDivide(dividend: bigint, divisor: bigint, fieldModulus: bigint): bigint {
	return dividend * modularMultiplicitiveInverse(divisor, fieldModulus) % fieldModulus
}

export function modularMultiplicitiveInverse(base: bigint, fieldModulus: bigint): bigint {
	let power = fieldModulus - 2n
	let result = 1n
	while (power > 0n) {
		if (power % 2n) {
			result *= base
			result %= fieldModulus
		}
		power /= 2n
		base *= base
		base %= fieldModulus
	}
	return result
}

export function modularPower(base: bigint, exponent: bigint, modulus: bigint) {
	let result = 1n
	base = base % modulus
	while (exponent > 0) {
		if (exponent % 2n == 1n)
			result = (result * base) % modulus
		exponent = exponent >> 1n
		base = (base * base) % modulus
	}
	return result
}

export function modularGreatestCommonDenominator(a: bigint, b: bigint): bigint {
	return (b == 0n) ? a : modularGreatestCommonDenominator(b, a % b)
}

export function getFirstBits(data: Uint8Array, numberOfBits: number): Array<boolean> {
	if (numberOfBits > 32) throw new Error(`Can only strip off up to the first 32 bits.`)
	const result = new Array<boolean>()
	for (let i = 0; i < numberOfBits; ++i) {
		result.push(getBit(data[Math.floor(i / 8)], i % 8))
	}
	return result
}

export function toBitArray(data: Uint8Array): Array<boolean> {
	const result = new Array<boolean>()
	for (let byte of data) {
		for (let i = 0; i < 8; ++i) {
			result.push(getBit(byte, i))
		}
	}
	return result
}

export function getBit(data: number, offset: number): boolean {
	if (data >= 2**8) throw new Error(`Only supports 8-bit numbers`)
	return !!((data >>> (8 - offset - 1)) & 0b1)
}

export function bitArrayToNumber(data: Array<boolean>): number {
	let result = 0
	for (let i = 0; i < data.length; ++i) {
		result = result ^ Number(data[i]) << (data.length - i - 1)
	}
	return result
}

export function modularHasPerfectSquareRoot(value: bigint, modulus: bigint) {
	if (value === 0n) throw new Error(`value cannot be 0`)
	// technically this can work for values greater than or equal to modulus, but we would need to deal with value % modulus == 0 then
	if (value >= modulus) throw new Error(`value (${value}) >= modulus (${modulus})`)
	const legendreSymbol = modularPower(value, (modulus - 1n) / 2n, modulus)
	// legendareSymbol will always be -1 or 1 here (0 is not possible because we don't allow value >= modulus)
	return legendreSymbol === 1n ? true : false
}

/**
 *
 * @param value Must be less modulus and greater than 0.
 * @param modulus Must be prime.
 * @returns A tuple containing the two roots,
 */
export function modularTryFindPerfectSquareRoot(value: bigint, modulus: bigint) {
	if (value === 0n) return undefined
	if (!modularHasPerfectSquareRoot(value, modulus)) return undefined
	if (modulus === 2n) return undefined
	if (modulus % 4n === 3n) {
		const result = modularPower(value, (modulus + 1n) / 4n, modulus)
		return (result > modulus / 2n) ? [result, modulus - result] as const : [modulus - result, result] as const
	}

	// reduce powers of 2 from modulus-1 to find our starting exponents
	// TODO: figure out some better names for these variables, these absolutely suck
	let s = modulus - 1n
	let exponent = 0n
	while (s % 2n === 0n) {
		s /= 2n
		exponent += 1n
	}

	// find a value that that has a perfect square root of modulus
	// TODO: cache this, or take it as a parameter since it is constant for a given modulus
	let smallestWithoutPerfectSquare = 2n
	while (modularHasPerfectSquareRoot(smallestWithoutPerfectSquare++, modulus)) {}

	// Tonelli-Shanks
	let currentGuess = modularPower(value, (s + 1n) / 2n, modulus)
	let fudgeFactor = modularPower(value, s, modulus)
	let g = modularPower(smallestWithoutPerfectSquare, s, modulus)

	while (true) {
		if (fudgeFactor === 1n) return (currentGuess > modulus / 2n) ? [currentGuess, modulus - currentGuess] as const : [modulus - currentGuess, currentGuess] as const
		let tempFudgeFactor = fudgeFactor
		let i = 0
		for (; i < exponent; ++i) {
			if (tempFudgeFactor === 1n) break
			tempFudgeFactor = modularPower(tempFudgeFactor, 2n, modulus)
		}
		// TODO: find a better name for this variable
		const gs = modularPower(g, 2n**(exponent - BigInt(i) - 1n), modulus)
		g = (gs * gs) % modulus
		currentGuess = (currentGuess * gs) % modulus
		fudgeFactor = (fudgeFactor * g) % modulus
		exponent = BigInt(i)
	}
}
