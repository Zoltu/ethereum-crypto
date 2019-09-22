declare module 'base-58' {
	export function encode(input: Uint8Array): string
	export function decode(input: string): Buffer
}
