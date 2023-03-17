import { leftCircularShift64, validateByteArray } from './utilities.js'

const roundConstants = [
	0x0000000000000001n, 0x0000000000008082n, 0x800000000000808An, 0x8000000080008000n, 0x000000000000808Bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n, 0x000000000000008An, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000An, 0x000000008000808Bn, 0x800000000000008Bn, 0x8000000000008089n, 0x8000000000008003n, 0x8000000000008002n, 0x8000000000000080n, 0x000000000000800An, 0x800000008000000An, 0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n
]

const rotationOffests = [
	[0n, 36n, 3n, 41n, 18n],
	[1n, 44n, 10n, 45n, 2n],
	[62n, 6n, 43n, 15n, 61n],
	[28n, 55n, 25n, 21n, 56n],
	[27n, 20n, 39n, 8n, 14n],
]

function round(state: bigint[][], roundConstant: bigint): void {
	// θ step
	const tempC: bigint[] = []
	for (let x = 0; x < 5; ++x) {
		tempC[x] = state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4]
	}
	const tempD: bigint[] = []
	for (let x = 0; x < 5; ++x) {
		tempD[x] = tempC[(x+4) % 5] ^ leftCircularShift64(tempC[(x+1) % 5], 1n)
	}
	for (let x = 0; x < 5; ++x) {
		for (let y = 0; y < 5; ++y) {
			state[x][y] ^= tempD[x]
		}
	}

	// ρ and π steps
	const tempB: bigint[][] = [[0n,0n,0n,0n,0n],[0n,0n,0n,0n,0n],[0n,0n,0n,0n,0n],[0n,0n,0n,0n,0n],[0n,0n,0n,0n,0n]]
	for (let x = 0; x < 5; ++x) {
		for (let y = 0; y < 5; ++y) {
			tempB[y][(2*x + 3*y) % 5] = leftCircularShift64(state[x][y], rotationOffests[x][y])
		}
	}

	// χ step
	for (let x = 0; x < 5; ++x) {
		for (let y = 0; y < 5; ++y) {
			state[x][y] = tempB[x][y] ^ ((~tempB[(x+1) % 5][y]) & tempB[(x+2) % 5][y])
		}
	}

	// ι step
	state[0][0] ^= roundConstant
}

function permute(state: bigint[][]): void {
	for (const roundConstant of roundConstants) {
		round(state, roundConstant)
	}
}

export async function hash(message: Iterable<number> & {length:number}): Promise<bigint> {
	validateByteArray(message)

	// padding
	const paddingLength = 136 - (message.length % 136)
	const padding = new Array(paddingLength).fill(0)
	padding[0] = 0x01
	const paddedMessage = new Uint8Array([...message, ...padding])
	paddedMessage[paddedMessage.length - 1] |= 0x80

	// initialization
	const state: bigint[][] = [[0n,0n,0n,0n,0n],[0n,0n,0n,0n,0n],[0n,0n,0n,0n,0n],[0n,0n,0n,0n,0n],[0n,0n,0n,0n,0n]]
	for (let x = 0; x < 5; ++x) {
		for (let y = 0; y < 5; ++y) {
			state[x][y] = 0n
		}
	}

	// absorbing phase
	for (let i = 0; i < paddedMessage.length; i += 136) {
		const messageChunk = new DataView(paddedMessage.buffer, i, 136)
		for (let j = 0; j < 17; ++j) {
			const x = j % 5
			const y = Math.floor(j / 5)
			state[x][y] ^= messageChunk.getBigUint64(j * 8, true)
		}
		permute(state)
	}

	// squeezing phase
	const result = new Uint8Array(32) as Uint8Array & {length:32}
	const resultView = new DataView(result.buffer)
	resultView.setBigInt64(0, state[0][0], true)
	resultView.setBigInt64(8, state[1][0], true)
	resultView.setBigInt64(16, state[2][0], true)
	resultView.setBigInt64(24, state[3][0], true)

	// this keccak256 implementation follows the reference implementation which assumes little endian, including its constants and how it converts the input byte array.  This means that the values in our state array are all byte-order swapped.  The keccak algorithm doesn't actually care what the numbers are, so it still works as long as we flip the byte order around on the way out.
	// TODO: figure out how to convert this implementation to use big endian.  Requires changing `messageChunk.getBigUint64(..., false)`, removing the endian swap here, swapping all of the round constants, and figuring out what to do with the padding.
	return endianSwap64(state[0][0]) << 192n ^ endianSwap64(state[1][0]) << 128n ^ endianSwap64(state[2][0]) << 64n ^ endianSwap64(state[3][0])
}

function endianSwap64(value: bigint): bigint {
	return ((value & 0x00000000000000ffn) << 56n)
		^ ((value & 0x000000000000ff00n) << 40n)
		^ ((value & 0x0000000000ff0000n) << 24n)
		^ ((value & 0x00000000ff000000n) << 8n)
		^ ((value & 0x000000ff00000000n) >> 8n)
		^ ((value & 0x0000ff0000000000n) >> 24n)
		^ ((value & 0x00ff000000000000n) >> 40n)
		^ ((value & 0xff00000000000000n) >> 56n)
}
