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
