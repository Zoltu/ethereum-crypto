import Jasmine = require('jasmine');
const jasmine = new Jasmine({})

import { mnemonic, secp256k1, keccak256, hdWallet, ethereum } from '@zoltu/ethereum-crypto'
import { Crypto } from '@peculiar/webcrypto'
import * as Base58 from 'base-58'
import { TextEncoder } from 'util'
(global as any).crypto = new Crypto()

describe('mnemonic', () => {
	describe('generateMnemonic', () => {
		it('128 bits is 12 words', async () => {
			const words = await mnemonic.generateRandom(128)
			expect(words.length).toEqual(12)
		})
		it('256 bits is 24 words', async () => {
			const words = await mnemonic.generateRandom(256)
			expect(words.length).toEqual(24)
		})
	})

	// https://github.com/trezor/python-mnemonic/blob/master/vectors.json
	const vectors = [
		[
			"00000000000000000000000000000000",
			"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
			"TREZOR",
			"c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
			"xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF",
		],
		[
			"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
			"legal winner thank year wave sausage worth useful legal winner thank yellow",
			"TREZOR",
			"2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
			"xprv9s21ZrQH143K2gA81bYFHqU68xz1cX2APaSq5tt6MFSLeXnCKV1RVUJt9FWNTbrrryem4ZckN8k4Ls1H6nwdvDTvnV7zEXs2HgPezuVccsq",
		],
		[
			"80808080808080808080808080808080",
			"letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
			"TREZOR",
			"d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8",
			"xprv9s21ZrQH143K2shfP28KM3nr5Ap1SXjz8gc2rAqqMEynmjt6o1qboCDpxckqXavCwdnYds6yBHZGKHv7ef2eTXy461PXUjBFQg6PrwY4Gzq",
		],
		[
			"ffffffffffffffffffffffffffffffff",
			"zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
			"TREZOR",
			"ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069",
			"xprv9s21ZrQH143K2V4oox4M8Zmhi2Fjx5XK4Lf7GKRvPSgydU3mjZuKGCTg7UPiBUD7ydVPvSLtg9hjp7MQTYsW67rZHAXeccqYqrsx8LcXnyd",
		],
		[
			"000000000000000000000000000000000000000000000000",
			"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
			"TREZOR",
			"035895f2f481b1b0f01fcf8c289c794660b289981a78f8106447707fdd9666ca06da5a9a565181599b79f53b844d8a71dd9f439c52a3d7b3e8a79c906ac845fa",
			"xprv9s21ZrQH143K3mEDrypcZ2usWqFgzKB6jBBx9B6GfC7fu26X6hPRzVjzkqkPvDqp6g5eypdk6cyhGnBngbjeHTe4LsuLG1cCmKJka5SMkmU",
		],
		[
			"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
			"legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
			"TREZOR",
			"f2b94508732bcbacbcc020faefecfc89feafa6649a5491b8c952cede496c214a0c7b3c392d168748f2d4a612bada0753b52a1c7ac53c1e93abd5c6320b9e95dd",
			"xprv9s21ZrQH143K3Lv9MZLj16np5GzLe7tDKQfVusBni7toqJGcnKRtHSxUwbKUyUWiwpK55g1DUSsw76TF1T93VT4gz4wt5RM23pkaQLnvBh7",
		],
		[
			"808080808080808080808080808080808080808080808080",
			"letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
			"TREZOR",
			"107d7c02a5aa6f38c58083ff74f04c607c2d2c0ecc55501dadd72d025b751bc27fe913ffb796f841c49b1d33b610cf0e91d3aa239027f5e99fe4ce9e5088cd65",
			"xprv9s21ZrQH143K3VPCbxbUtpkh9pRG371UCLDz3BjceqP1jz7XZsQ5EnNkYAEkfeZp62cDNj13ZTEVG1TEro9sZ9grfRmcYWLBhCocViKEJae",
		],
		[
			"ffffffffffffffffffffffffffffffffffffffffffffffff",
			"zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
			"TREZOR",
			"0cd6e5d827bb62eb8fc1e262254223817fd068a74b5b449cc2f667c3f1f985a76379b43348d952e2265b4cd129090758b3e3c2c49103b5051aac2eaeb890a528",
			"xprv9s21ZrQH143K36Ao5jHRVhFGDbLP6FCx8BEEmpru77ef3bmA928BxsqvVM27WnvvyfWywiFN8K6yToqMaGYfzS6Db1EHAXT5TuyCLBXUfdm",
		],
		[
			"0000000000000000000000000000000000000000000000000000000000000000",
			"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
			"TREZOR",
			"bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
			"xprv9s21ZrQH143K32qBagUJAMU2LsHg3ka7jqMcV98Y7gVeVyNStwYS3U7yVVoDZ4btbRNf4h6ibWpY22iRmXq35qgLs79f312g2kj5539ebPM",
		],
		[
			"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
			"legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
			"TREZOR",
			"bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a4021b146ad717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87",
			"xprv9s21ZrQH143K3Y1sd2XVu9wtqxJRvybCfAetjUrMMco6r3v9qZTBeXiBZkS8JxWbcGJZyio8TrZtm6pkbzG8SYt1sxwNLh3Wx7to5pgiVFU",
		],
		[
			"8080808080808080808080808080808080808080808080808080808080808080",
			"letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
			"TREZOR",
			"c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09e2ef61af0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f",
			"xprv9s21ZrQH143K3CSnQNYC3MqAAqHwxeTLhDbhF43A4ss4ciWNmCY9zQGvAKUSqVUf2vPHBTSE1rB2pg4avopqSiLVzXEU8KziNnVPauTqLRo",
		],
		[
			"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			"zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
			"TREZOR",
			"dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad",
			"xprv9s21ZrQH143K2WFF16X85T2QCpndrGwx6GueB72Zf3AHwHJaknRXNF37ZmDrtHrrLSHvbuRejXcnYxoZKvRquTPyp2JiNG3XcjQyzSEgqCB",
		],
		[
			"9e885d952ad362caeb4efe34a8e91bd2",
			"ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
			"TREZOR",
			"274ddc525802f7c828d8ef7ddbcdc5304e87ac3535913611fbbfa986d0c9e5476c91689f9c8a54fd55bd38606aa6a8595ad213d4c9c9f9aca3fb217069a41028",
			"xprv9s21ZrQH143K2oZ9stBYpoaZ2ktHj7jLz7iMqpgg1En8kKFTXJHsjxry1JbKH19YrDTicVwKPehFKTbmaxgVEc5TpHdS1aYhB2s9aFJBeJH",
		],
		[
			"6610b25967cdcca9d59875f5cb50b0ea75433311869e930b",
			"gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog",
			"TREZOR",
			"628c3827a8823298ee685db84f55caa34b5cc195a778e52d45f59bcf75aba68e4d7590e101dc414bc1bbd5737666fbbef35d1f1903953b66624f910feef245ac",
			"xprv9s21ZrQH143K3uT8eQowUjsxrmsA9YUuQQK1RLqFufzybxD6DH6gPY7NjJ5G3EPHjsWDrs9iivSbmvjc9DQJbJGatfa9pv4MZ3wjr8qWPAK",
		],
		[
			"68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
			"hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
			"TREZOR",
			"64c87cde7e12ecf6704ab95bb1408bef047c22db4cc7491c4271d170a1b213d20b385bc1588d9c7b38f1b39d415665b8a9030c9ec653d75e65f847d8fc1fc440",
			"xprv9s21ZrQH143K2XTAhys3pMNcGn261Fi5Ta2Pw8PwaVPhg3D8DWkzWQwjTJfskj8ofb81i9NP2cUNKxwjueJHHMQAnxtivTA75uUFqPFeWzk",
		],
		[
			"c0ba5a8e914111210f2bd131f3d5e08d",
			"scheme spot photo card baby mountain device kick cradle pact join borrow",
			"TREZOR",
			"ea725895aaae8d4c1cf682c1bfd2d358d52ed9f0f0591131b559e2724bb234fca05aa9c02c57407e04ee9dc3b454aa63fbff483a8b11de949624b9f1831a9612",
			"xprv9s21ZrQH143K3FperxDp8vFsFycKCRcJGAFmcV7umQmcnMZaLtZRt13QJDsoS5F6oYT6BB4sS6zmTmyQAEkJKxJ7yByDNtRe5asP2jFGhT6",
		],
		[
			"6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3",
			"horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave",
			"TREZOR",
			"fd579828af3da1d32544ce4db5c73d53fc8acc4ddb1e3b251a31179cdb71e853c56d2fcb11aed39898ce6c34b10b5382772db8796e52837b54468aeb312cfc3d",
			"xprv9s21ZrQH143K3R1SfVZZLtVbXEB9ryVxmVtVMsMwmEyEvgXN6Q84LKkLRmf4ST6QrLeBm3jQsb9gx1uo23TS7vo3vAkZGZz71uuLCcywUkt",
		],
		[
			"9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863",
			"panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside",
			"TREZOR",
			"72be8e052fc4919d2adf28d5306b5474b0069df35b02303de8c1729c9538dbb6fc2d731d5f832193cd9fb6aeecbc469594a70e3dd50811b5067f3b88b28c3e8d",
			"xprv9s21ZrQH143K2WNnKmssvZYM96VAr47iHUQUTUyUXH3sAGNjhJANddnhw3i3y3pBbRAVk5M5qUGFr4rHbEWwXgX4qrvrceifCYQJbbFDems",
		],
		[
			"23db8160a31d3e0dca3688ed941adbf3",
			"cat swing flag economy stadium alone churn speed unique patch report train",
			"TREZOR",
			"deb5f45449e615feff5640f2e49f933ff51895de3b4381832b3139941c57b59205a42480c52175b6efcffaa58a2503887c1e8b363a707256bdd2b587b46541f5",
			"xprv9s21ZrQH143K4G28omGMogEoYgDQuigBo8AFHAGDaJdqQ99QKMQ5J6fYTMfANTJy6xBmhvsNZ1CJzRZ64PWbnTFUn6CDV2FxoMDLXdk95DQ",
		],
		[
			"8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0",
			"light rule cinnamon wrap drastic word pride squirrel upgrade then income fatal apart sustain crack supply proud access",
			"TREZOR",
			"4cbdff1ca2db800fd61cae72a57475fdc6bab03e441fd63f96dabd1f183ef5b782925f00105f318309a7e9c3ea6967c7801e46c8a58082674c860a37b93eda02",
			"xprv9s21ZrQH143K3wtsvY8L2aZyxkiWULZH4vyQE5XkHTXkmx8gHo6RUEfH3Jyr6NwkJhvano7Xb2o6UqFKWHVo5scE31SGDCAUsgVhiUuUDyh",
		],
		[
			"066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad",
			"all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform",
			"TREZOR",
			"26e975ec644423f4a4c4f4215ef09b4bd7ef924e85d1d17c4cf3f136c2863cf6df0a475045652c57eb5fb41513ca2a2d67722b77e954b4b3fc11f7590449191d",
			"xprv9s21ZrQH143K3rEfqSM4QZRVmiMuSWY9wugscmaCjYja3SbUD3KPEB1a7QXJoajyR2T1SiXU7rFVRXMV9XdYVSZe7JoUXdP4SRHTxsT1nzm",
		],
		[
			"f30f8c1da665478f49b001d94c5fc452",
			"vessel ladder alter error federal sibling chat ability sun glass valve picture",
			"TREZOR",
			"2aaa9242daafcee6aa9d7269f17d4efe271e1b9a529178d7dc139cd18747090bf9d60295d0ce74309a78852a9caadf0af48aae1c6253839624076224374bc63f",
			"xprv9s21ZrQH143K2QWV9Wn8Vvs6jbqfF1YbTCdURQW9dLFKDovpKaKrqS3SEWsXCu6ZNky9PSAENg6c9AQYHcg4PjopRGGKmdD313ZHszymnps",
		],
		[
			"c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05",
			"scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump",
			"TREZOR",
			"7b4a10be9d98e6cba265566db7f136718e1398c71cb581e1b2f464cac1ceedf4f3e274dc270003c670ad8d02c4558b2f8e39edea2775c9e232c7cb798b069e88",
			"xprv9s21ZrQH143K4aERa2bq7559eMCCEs2QmmqVjUuzfy5eAeDX4mqZffkYwpzGQRE2YEEeLVRoH4CSHxianrFaVnMN2RYaPUZJhJx8S5j6puX",
		],
		[
			"f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
			"void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
			"TREZOR",
			"01f5bced59dec48e362f2c45b5de68b9fd6c92c6634f44d6d40aab69056506f0e35524a518034ddc1192e1dacd32c1ed3eaa3c3b131c88ed8e7e54c49a5d0998",
			"xprv9s21ZrQH143K39rnQJknpH1WEPFJrzmAqqasiDcVrNuk926oizzJDDQkdiTvNPr2FYDYzWgiMiC63YmfPAa2oPyNB23r2g7d1yiK6WpqaQS",
		]
	] as const

	describe('generateMnemonicFromEntropy', () => {
		for (const [entropy, expectedMnemonic] of vectors) {
			it(entropy, async () => {
				const words = await mnemonic.generateFromEntropy(Uint8Array.from(Buffer.from(entropy, 'hex')))
				expect(words).toEqual(expectedMnemonic.split(' '))
			})
		}
	})

	describe('mnemonicToSeed', () => {
		for (const [, words, passphrase, expectedSeedHex] of vectors) {
			it(words, async () => {
				const expectedSeed = bytesToBigint(Buffer.from(expectedSeedHex, 'hex'))
				const seed = await mnemonic.toSeed(words.split(' '), passphrase)
				expect(seed).toEqual(expectedSeed)
			})
		}
	})

	describe('to private key derivation path: `m`', () => {
		for (const [, words, passphrase, , base58ExpectedPrivateKey] of vectors) {
			it(words, async () => {
				const expectedPrivateKey = bytesToBigint(Base58.decode(base58ExpectedPrivateKey).subarray(46, 78))
				const seed = await mnemonic.toSeed(words.split(' '), passphrase)
				const privateKey = await hdWallet.privateKeyFromSeed(bigintToBytes(seed, 64), 'm')
				expect(privateKey).toEqual(expectedPrivateKey)
			})
		}
	})
})

describe('secp256k1', () => {
	describe('generatePrivateKey', () => {
		xit('eyeball randomness', async () => {
			// this is a random number generator, there isn't really anything to test.
			const bitDistribution = new Array(256).fill(0)
			for (let i = 0; i < 1000000; ++i) {
				const privateKey = await secp256k1.generatePrivateKey()
				for (let j = 0n; j < 256n; ++j) {
					if (privateKey & 2n**j) ++bitDistribution[Number(j)]
				}
			}
			// eyeball this value, expect most of the bits to hover around 500,000
			bitDistribution
		})
	})

	describe('privateKeyToPublicKey', () => {
		it('1', async () => {
			// from elliptic NPM package
			const expected = {
				x: 55066263022277343669578718895168534326250603453777594175500187360389116729240n,
				y: 32670510020758816978083085130507043184471273380659243275938904335757337482424n,
				z: 1n,
			} as const
			const publicKey = await secp256k1.privateKeyToPublicKey(1n)
			expect(publicKey).toEqual(expected)
		})
		it('2', async () => {
			// from elliptic NPM package
			const expected = {
				x: 89565891926547004231252920425935692360644145829622209833684329913297188986597n,
				y: 12158399299693830322967808612713398636155367887041628176798871954788371653930n,
				z: 1n,
			} as const
			const publicKey = await secp256k1.privateKeyToPublicKey(2n)
			expect(publicKey).toEqual(expected)
		})
		it('3', async () => {
			// from elliptic NPM package
			const expected = {
				x: 112711660439710606056748659173929673102114977341539408544630613555209775888121n,
				y: 25583027980570883691656905877401976406448868254816295069919888960541586679410n,
				z: 1n,
			} as const
			const publicKey = await secp256k1.privateKeyToPublicKey(3n)
			expect(publicKey).toEqual(expected)
		})
		it('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140n', async () => {
			// from elliptic NPM package
			const expected = {
				x: 55066263022277343669578718895168534326250603453777594175500187360389116729240n,
				y: 83121579216557378445487899878180864668798711284981320763518679672151497189239n,
				z: 1n,
			} as const
			const publicKey = await secp256k1.privateKeyToPublicKey(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140n)
			expect(publicKey).toEqual(expected)
		})
		it('97ddae0f3a25b92268175400149d65d6887b9cefaf28ea2c078e05cdc15a3c0a', async () => {
			// from https://gist.github.com/nakov/1dcbe26988e18f7a4d013b65d8803ffc#gistcomment-2401121
			const expected = {
				x: 0x7b83ad6afb1209f3c82ebeb08c0c5fa9bf6724548506f2fb4f991e2287a77090n,
				y: 0x177316ca82b0bdf70cd9dee145c3002c0da1d92626449875972a27807b73b42en,
				z: 1n,
			} as const
			const publicKey = await secp256k1.privateKeyToPublicKey(0x97ddae0f3a25b92268175400149d65d6887b9cefaf28ea2c078e05cdc15a3c0an)
			expect(publicKey).toEqual(expected)
		})
		it('97ddae0f3a25b92268175400149d65d6887b9cefaf28ea2c078e05cdc15a3c0a', async () => {
			// from https://crypto.stackexchange.com/q/41316
			const expected = {
				x: 0x3AF1E1EFA4D1E1AD5CB9E3967E98E901DAFCD37C44CF0BFB6C216997F5EE51DFn,
				y: 0xE4ACAC3E6F139E0C7DB2BD736824F51392BDA176965A1C59EB9C3C5FF9E85D7An,
				z: 1n,
			} as const
			const publicKey = await secp256k1.privateKeyToPublicKey(0xD30519BCAE8D180DBFCC94FE0B8383DC310185B0BE97B4365083EBCECCD75759n)
			expect(publicKey).toEqual(expected)
		})

		// from https://crypto.stackexchange.com/a/21206
		const vectors = [
			[ 1n, 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n ],
			[ 2n, 0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5n, 0x1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52An ],
			[ 3n, 0xF9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9n, 0x388F7B0F632DE8140FE337E62A37F3566500A99934C2231B6CB9FD7584B8E672n ],
			[ 4n, 0xE493DBF1C10D80F3581E4904930B1404CC6C13900EE0758474FA94ABE8C4CD13n, 0x51ED993EA0D455B75642E2098EA51448D967AE33BFBDFE40CFE97BDC47739922n ],
			[ 5n, 0x2F8BDE4D1A07209355B4A7250A5C5128E88B84BDDC619AB7CBA8D569B240EFE4n, 0xD8AC222636E5E3D6D4DBA9DDA6C9C426F788271BAB0D6840DCA87D3AA6AC62D6n ],
			[ 6n, 0xFFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A1460297556n, 0xAE12777AACFBB620F3BE96017F45C560DE80F0F6518FE4A03C870C36B075F297n ],
			[ 7n, 0x5CBDF0646E5DB4EAA398F365F2EA7A0E3D419B7E0330E39CE92BDDEDCAC4F9BCn, 0x6AEBCA40BA255960A3178D6D861A54DBA813D0B813FDE7B5A5082628087264DAn ],
			[ 8n, 0x2F01E5E15CCA351DAFF3843FB70F3C2F0A1BDD05E5AF888A67784EF3E10A2A01n, 0x5C4DA8A741539949293D082A132D13B4C2E213D6BA5B7617B5DA2CB76CBDE904n ],
			[ 9n, 0xACD484E2F0C7F65309AD178A9F559ABDE09796974C57E714C35F110DFC27CCBEn, 0xCC338921B0A7D9FD64380971763B61E9ADD888A4375F8E0F05CC262AC64F9C37n ],
			[ 10n, 0xA0434D9E47F3C86235477C7B1AE6AE5D3442D49B1943C2B752A68E2A47E247C7n, 0x893ABA425419BC27A3B6C7E693A24C696F794C2ED877A1593CBEE53B037368D7n ],
			[ 11n, 0x774AE7F858A9411E5EF4246B70C65AAC5649980BE5C17891BBEC17895DA008CBn, 0xD984A032EB6B5E190243DD56D7B7B365372DB1E2DFF9D6A8301D74C9C953C61Bn ],
			[ 12n, 0xD01115D548E7561B15C38F004D734633687CF4419620095BC5B0F47070AFE85An, 0xA9F34FFDC815E0D7A8B64537E17BD81579238C5DD9A86D526B051B13F4062327n ],
			[ 13n, 0xF28773C2D975288BC7D1D205C3748651B075FBC6610E58CDDEEDDF8F19405AA8n, 0x0AB0902E8D880A89758212EB65CDAF473A1A06DA521FA91F29B5CB52DB03ED81n ],
			[ 14n, 0x499FDF9E895E719CFD64E67F07D38E3226AA7B63678949E6E49B241A60E823E4n, 0xCAC2F6C4B54E855190F044E4A7B3D464464279C27A3F95BCC65F40D403A13F5Bn ],
			[ 15n, 0xD7924D4F7D43EA965A465AE3095FF41131E5946F3C85F79E44ADBCF8E27E080En, 0x581E2872A86C72A683842EC228CC6DEFEA40AF2BD896D3A5C504DC9FF6A26B58n ],
			[ 16n, 0xE60FCE93B59E9EC53011AABC21C23E97B2A31369B87A5AE9C44EE89E2A6DEC0An, 0xF7E3507399E595929DB99F34F57937101296891E44D23F0BE1F32CCE69616821n ],
			[ 17n, 0xDEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34n, 0x4211AB0694635168E997B0EAD2A93DAECED1F4A04A95C0F6CFB199F69E56EB77n ],
			[ 18n, 0x5601570CB47F238D2B0286DB4A990FA0F3BA28D1A319F5E7CF55C2A2444DA7CCn, 0xC136C1DC0CBEB930E9E298043589351D81D8E0BC736AE2A1F5192E5E8B061D58n ],
			[ 19n, 0x2B4EA0A797A443D293EF5CFF444F4979F06ACFEBD7E86D277475656138385B6Cn, 0x85E89BC037945D93B343083B5A1C86131A01F60C50269763B570C854E5C09B7An ],
			[ 20n, 0x4CE119C96E2FA357200B559B2F7DD5A5F02D5290AFF74B03F3E471B273211C97n, 0x12BA26DCB10EC1625DA61FA10A844C676162948271D96967450288EE9233DC3An ],
			[ 112233445566778899n, 0xA90CC3D3F3E146DAADFC74CA1372207CB4B725AE708CEF713A98EDD73D99EF29n, 0x5A79D6B289610C68BC3B47F3D72F9788A26A06868B4D8E433E1E2AD76FB7DC76n ],
			[ 112233445566778899112233445566778899n, 0xE5A2636BCFD412EBF36EC45B19BFB68A1BC5F8632E678132B885F7DF99C5E9B3n, 0x736C1CE161AE27B405CAFD2A7520370153C2C861AC51D6C1D5985D9606B45F39n ],
			[ 28948022309329048855892746252171976963209391069768726095651290785379540373584n, 0xA6B594B38FB3E77C6EDF78161FADE2041F4E09FD8497DB776E546C41567FEB3Cn, 0x71444009192228730CD8237A490FEBA2AFE3D27D7CC1136BC97E439D13330D55n ],
			[ 57896044618658097711785492504343953926418782139537452191302581570759080747168n, 0x00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C63n, 0x3F3979BF72AE8202983DC989AEC7F2FF2ED91BDD69CE02FC0700CA100E59DDF3n ],
			[ 86844066927987146567678238756515930889628173209306178286953872356138621120752n, 0xE24CE4BEEE294AA6350FAA67512B99D388693AE4E7F53D19882A6EA169FC1CE1n, 0x8B71E83545FC2B5872589F99D948C03108D36797C4DE363EBD3FF6A9E1A95B10n ],
			[ 115792089237316195423570985008687907852837564279074904382605163141518161494317n, 0x4CE119C96E2FA357200B559B2F7DD5A5F02D5290AFF74B03F3E471B273211C97n, 0xED45D9234EF13E9DA259E05EF57BB3989E9D6B7D8E269698BAFD77106DCC1FF5n ],
			[ 115792089237316195423570985008687907852837564279074904382605163141518161494318n, 0x2B4EA0A797A443D293EF5CFF444F4979F06ACFEBD7E86D277475656138385B6Cn, 0x7A17643FC86BA26C4CBCF7C4A5E379ECE5FE09F3AFD9689C4A8F37AA1A3F60B5n ],
			[ 115792089237316195423570985008687907852837564279074904382605163141518161494319n, 0x5601570CB47F238D2B0286DB4A990FA0F3BA28D1A319F5E7CF55C2A2444DA7CCn, 0x3EC93E23F34146CF161D67FBCA76CAE27E271F438C951D5E0AE6D1A074F9DED7n ],
			[ 115792089237316195423570985008687907852837564279074904382605163141518161494320n, 0xDEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34n, 0xBDEE54F96B9CAE9716684F152D56C251312E0B5FB56A3F09304E660861A910B8n ],
			[ 115792089237316195423570985008687907852837564279074904382605163141518161494321n, 0xE60FCE93B59E9EC53011AABC21C23E97B2A31369B87A5AE9C44EE89E2A6DEC0An, 0x081CAF8C661A6A6D624660CB0A86C8EFED6976E1BB2DC0F41E0CD330969E940En ],
			[ 115792089237316195423570985008687907852837564279074904382605163141518161494322n, 0xD7924D4F7D43EA965A465AE3095FF41131E5946F3C85F79E44ADBCF8E27E080En, 0xA7E1D78D57938D597C7BD13DD733921015BF50D427692C5A3AFB235F095D90D7n ],
			[ 115792089237316195423570985008687907852837564279074904382605163141518161494323n, 0x499FDF9E895E719CFD64E67F07D38E3226AA7B63678949E6E49B241A60E823E4n, 0x353D093B4AB17AAE6F0FBB1B584C2B9BB9BD863D85C06A4339A0BF2AFC5EBCD4n ],
			[ 115792089237316195423570985008687907852837564279074904382605163141518161494324n, 0xF28773C2D975288BC7D1D205C3748651B075FBC6610E58CDDEEDDF8F19405AA8n, 0xF54F6FD17277F5768A7DED149A3250B8C5E5F925ADE056E0D64A34AC24FC0EAEn ],
			[ 115792089237316195423570985008687907852837564279074904382605163141518161494325n, 0xD01115D548E7561B15C38F004D734633687CF4419620095BC5B0F47070AFE85An, 0x560CB00237EA1F285749BAC81E8427EA86DC73A2265792AD94FAE4EB0BF9D908n ],
			[ 115792089237316195423570985008687907852837564279074904382605163141518161494326n, 0x774AE7F858A9411E5EF4246B70C65AAC5649980BE5C17891BBEC17895DA008CBn, 0x267B5FCD1494A1E6FDBC22A928484C9AC8D24E1D20062957CFE28B3536AC3614n ],
			[ 115792089237316195423570985008687907852837564279074904382605163141518161494327n, 0xA0434D9E47F3C86235477C7B1AE6AE5D3442D49B1943C2B752A68E2A47E247C7n, 0x76C545BDABE643D85C4938196C5DB3969086B3D127885EA6C3411AC3FC8C9358n ],
			[ 115792089237316195423570985008687907852837564279074904382605163141518161494328n, 0xACD484E2F0C7F65309AD178A9F559ABDE09796974C57E714C35F110DFC27CCBEn, 0x33CC76DE4F5826029BC7F68E89C49E165227775BC8A071F0FA33D9D439B05FF8n ],
			[ 115792089237316195423570985008687907852837564279074904382605163141518161494329n, 0x2F01E5E15CCA351DAFF3843FB70F3C2F0A1BDD05E5AF888A67784EF3E10A2A01n, 0xA3B25758BEAC66B6D6C2F7D5ECD2EC4B3D1DEC2945A489E84A25D3479342132Bn ],
			[ 115792089237316195423570985008687907852837564279074904382605163141518161494330n, 0x5CBDF0646E5DB4EAA398F365F2EA7A0E3D419B7E0330E39CE92BDDEDCAC4F9BCn, 0x951435BF45DAA69F5CE8729279E5AB2457EC2F47EC02184A5AF7D9D6F78D9755n ],
			[ 115792089237316195423570985008687907852837564279074904382605163141518161494331n, 0xFFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A1460297556n, 0x51ED8885530449DF0C4169FE80BA3A9F217F0F09AE701B5FC378F3C84F8A0998n ],
			[ 115792089237316195423570985008687907852837564279074904382605163141518161494332n, 0x2F8BDE4D1A07209355B4A7250A5C5128E88B84BDDC619AB7CBA8D569B240EFE4n, 0x2753DDD9C91A1C292B24562259363BD90877D8E454F297BF235782C459539959n ],
			[ 115792089237316195423570985008687907852837564279074904382605163141518161494333n, 0xE493DBF1C10D80F3581E4904930B1404CC6C13900EE0758474FA94ABE8C4CD13n, 0xAE1266C15F2BAA48A9BD1DF6715AEBB7269851CC404201BF30168422B88C630Dn ],
			[ 115792089237316195423570985008687907852837564279074904382605163141518161494334n, 0xF9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9n, 0xC77084F09CD217EBF01CC819D5C80CA99AFF5666CB3DDCE4934602897B4715BDn ],
			[ 115792089237316195423570985008687907852837564279074904382605163141518161494335n, 0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5n, 0xE51E970159C23CC65C3A7BE6B99315110809CD9ACD992F1EDC9BCE55AF301705n ],
			[ 115792089237316195423570985008687907852837564279074904382605163141518161494336n, 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n, 0xB7C52588D95C3B9AA25B0403F1EEF75702E84BB7597AABE663B82F6F04EF2777n ],
		]
		for (const [privateKey, expectedX, expectedY] of vectors) {
			it(`${privateKey}`, async () => {
				const expected = {
					x: expectedX,
					y: expectedY,
					z: 1n,
				} as const
				const publicKey = await secp256k1.privateKeyToPublicKey(privateKey)
				expect(publicKey).toEqual(expected)
			})
		}
	})

	describe('encodePoint', () => {
		it('0', () => {
			const encoded = secp256k1.encodePoint({x: 0n, y: 0n})
			expect(Array.from(encoded)).toEqual([4,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0])
		})
		it('1', () => {
			const encoded = secp256k1.encodePoint({x: 1n, y: 1n})
			expect(Array.from(encoded)).toEqual([4,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1])
		})
		it('max', () => {
			const encoded = secp256k1.encodePoint({x: 2n**256n-1n, y: 2n**256n-1n})
			expect(Array.from(encoded)).toEqual([4,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff])
		})
		it('x max, y 0', () => {
			const encoded = secp256k1.encodePoint({x: 2n**256n-1n, y: 0n})
			expect(Array.from(encoded)).toEqual([4,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0])
		})
	})

	describe('decodePoint', () => {
		it('0', () => {
			const decoded = secp256k1.decodePoint([4,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0] as const)
			expect(decoded).toEqual({x: 1n, y: 1n, z: 0n})
		})
		it('1', () => {
			const decoded = secp256k1.decodePoint([4,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1] as const)
			expect(decoded).toEqual({x: 1n, y: 1n, z: 1n})
		})
		it('max', () => {
			const decoded = secp256k1.decodePoint([4,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff] as const)
			expect(decoded).toEqual({x: 2n**256n-1n, y: 2n**256n-1n, z: 1n})
		})
		it('x max, y 0', () => {
			const decoded = secp256k1.decodePoint([4,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0] as const)
			expect(decoded).toEqual({x: 2n**256n-1n, y: 0n, z: 1n})
		})
	})

	describe('sign', () => {
		it('1, hello', async () => {
			const privateKey = 1n
			const messageHash = 12910348618308260923200348219926901280687058984330794534952861439530514639560n // UTF-8 encoded 'hello'
			const signature = await secp256k1.sign(privateKey, messageHash)
			expect(signature.r).toEqual(30415856915483355694770010044347290925834757931662916779572802233109910335221n)
			expect(signature.s).toEqual(38666684314969465487158487761466865909839606684532244836799039564262637080996n)
			expect(signature.recoveryParameter).toEqual(0)
		})
		it(`biggest key, hello`, async () => {
			const privateKey = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n - 1n
			const messageHash = 12910348618308260923200348219926901280687058984330794534952861439530514639560n // UTF-8 encoded 'hello'
			const signature = await secp256k1.sign(privateKey, messageHash)
			expect(signature.r).toEqual(31574677649868758279962039294696365839148563835385626044145726519354494338356n)
			expect(signature.s).toEqual(23959442095247853440126392963074989652526589897721901548691523738010830434640n)
			expect(signature.recoveryParameter).toEqual(1)
		})
	})

	describe('verify', () => {
		it('1, hello', async () => {
			const message = new TextEncoder().encode(`hello`)
			const messageHash = await keccak256.hash(message)
			const privateKey = 1n
			const publicKey = await secp256k1.privateKeyToPublicKey(privateKey)
			const signature = { r: 30415856915483355694770010044347290925834757931662916779572802233109910335221n, s: 38666684314969465487158487761466865909839606684532244836799039564262637080996n }
			const valid = await secp256k1.verify(publicKey, messageHash, signature)
			expect(valid).toEqual(true)
		})
		it('1, ethereum hello', async () => {
			const message = new TextEncoder().encode(`\x19Ethereum Signed Message:\n5hello`)
			const messageHash = await keccak256.hash(message)
			const privateKey = 1n
			const publicKey = await secp256k1.privateKeyToPublicKey(privateKey)
			const signature = { r: 103971450176177714643557042981572514570117585915721523808868249554313735244206n, s: 5259501285923218377719486404094138176021472319928632716132134674704837414442n }
			const valid = await secp256k1.verify(publicKey, messageHash, signature)
			expect(valid).toEqual(true)
		})
		it('biggest key, hello', async () => {
			const message = new TextEncoder().encode(`hello`)
			const messageHash = await keccak256.hash(message)
			const privateKey = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n - 1n
			const publicKey = await secp256k1.privateKeyToPublicKey(privateKey)
			const signature = { r: 31574677649868758279962039294696365839148563835385626044145726519354494338356n, s: 23959442095247853440126392963074989652526589897721901548691523738010830434640n }
			const valid = await secp256k1.verify(publicKey, messageHash, signature)
			expect(valid).toEqual(true)
		})
		it('returns false on invalid signature', async () => {
			const message = new TextEncoder().encode(`hello`)
			const messageHash = await keccak256.hash(message)
			const privateKey = 1n
			const publicKey = await secp256k1.privateKeyToPublicKey(privateKey)
			const signature = { r: 1n, s: 1n }
			const valid = await secp256k1.verify(publicKey, messageHash, signature)
			expect(valid).toEqual(false)
		})
	})
})

describe('keccak256', () => {
	// tests cribbed from https://github.com/emn178/js-sha3/blob/master/tests/test.js
	it('empty string', async () => {
		const input = new TextEncoder().encode('')
		const expected = 0xC5D2460186F7233C927E7DB2DCC703C0E500B653CA82273B7BFAD8045D85A470n
		const actual = await keccak256.hash(input)
		expect(actual).toEqual(expected)
	})
	it('The quick brown fox jumps over the lazy dog', async () => {
		const input = new TextEncoder().encode('The quick brown fox jumps over the lazy dog')
		const expected = 0x4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15n
		const actual = await keccak256.hash(input)
		expect(actual).toEqual(expected)
	})
	it('The quick brown fox jumps over the lazy dog.', async () => {
		const input = new TextEncoder().encode('The quick brown fox jumps over the lazy dog.')
		const expected = 0x578951e24efd62a3d63a86f7cd19aaa53c898fe287d2552133220370240b572dn
		const actual = await keccak256.hash(input)
		expect(actual).toEqual(expected)
	})
	it('long ascii string', async () => {
		const input = new TextEncoder().encode('The MD5 message-digest algorithm is a widely used cryptographic hash function producing a 128-bit (16-byte) hash value, typically expressed in text format as a 32 digit hexadecimal number. MD5 has been utilized in a wide variety of cryptographic applications, and is also commonly used to verify data integrity.')
		const expected = 0xaf20018353ffb50d507f1555580f5272eca7fdab4f8295db4b1a9ad832c93f6dn
		const actual = await keccak256.hash(input)
		expect(actual).toEqual(expected)
	})
	it(`中文`, async () => {
		const input = new TextEncoder().encode('中文')
		const expected = 0x70a2b6579047f0a977fcb5e9120a4e07067bea9abb6916fbc2d13ffb9a4e4eeen
		const actual = await keccak256.hash(input)
		expect(actual).toEqual(expected)
	})
	it('boundary length 1', async () => {
		const input = new TextEncoder().encode('012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234')
		const expected = 0xe1c34dc088c34f47a3d746bb2cdd07231130c59a9727360e79f4a264e949cb87n
		const actual = await keccak256.hash(input)
		expect(actual).toEqual(expected)
	})
	it('boundary length 2', async () => {
		const input = new TextEncoder().encode('0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345')
		const expected = 0x01247d7ddfd57394d74920f8ffeefcb196ba43c15801b6888a34a383c2866088n
		const actual = await keccak256.hash(input)
		expect(actual).toEqual(expected)
	})
	it('boundary length 1', async () => {
		const input = new TextEncoder().encode('01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456')
		const expected = 0xb6086ab48f4c24720d6e4d136b3e73c1a8406a2dc3295c3d1b66e0c85fd791ccn
		const actual = await keccak256.hash(input)
		expect(actual).toEqual(expected)
	})
})

describe('hdwallet', () => {
	describe('empty seed', () => {
		const seed = bigintToBytes(0n, 64)
		it('master', async () => {
			const path = `m`
			const expected = 0xeafd15702fca3f80beb565e66f19e20bbad0a34b46bb12075cbf1c5d94bb27d2n
			const privateKey = await hdWallet.privateKeyFromSeed(seed, path)
			expect(privateKey).toEqual(expected)
		})
		it('simple hardened path', async () => {
			const path = `m/0'`
			const expected = 0xcce45cf2c0dba4c3879f86d20fd0d51a5a7cdc4ea9054187ca812f50eedbd022n
			const privateKey = await hdWallet.privateKeyFromSeed(seed, path)
			expect(privateKey).toEqual(expected)
		})
		it('simple normal path', async () => {
			const path = `m/0`
			const expected = 0xcf89b3e2c86ad6886cf900703611e0dde1962afd2f2949b4c1d127d112449ff9n
			const privateKey = await hdWallet.privateKeyFromSeed(seed, path)
			expect(privateKey).toEqual(expected)
		})
	})
	describe('000102030405060708090a0b0c0d0e0f', () => {
		// from https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#Test_vector_1
		const seed = bigintToBytes(0x000102030405060708090a0b0c0d0e0fn, 16)
		it(`m`, async () => {
			const path = `m`
			const expected = 0xE8F32E723DECF4051AEFAC8E2C93C9C5B214313817CDB01A1494B917C8436B35n
			const privateKey = await hdWallet.privateKeyFromSeed(seed, path)
			expect(privateKey).toEqual(expected)
		})
		it(`m/0'`, async () => {
			const path = `m/0'`
			const expected = 0xEDB2E14F9EE77D26DD93B4ECEDE8D16ED408CE149B6CD80B0715A2D911A0AFEAn
			const privateKey = await hdWallet.privateKeyFromSeed(seed, path)
			expect(privateKey).toEqual(expected)
		})
		it(`m/0'/1`, async () => {
			const path = `m/0'/1`
			const expected = 0x3C6CB8D0F6A264C91EA8B5030FADAA8E538B020F0A387421A12DE9319DC93368n
			const privateKey = await hdWallet.privateKeyFromSeed(seed, path)
			expect(privateKey).toEqual(expected)
		})
		it(`m/0'/1/2'`, async () => {
			const path = `m/0'/1/2'`
			const expected = 0xCBCE0D719ECF7431D88E6A89FA1483E02E35092AF60C042B1DF2FF59FA424DCAn
			const privateKey = await hdWallet.privateKeyFromSeed(seed, path)
			expect(privateKey).toEqual(expected)
		})
		it(`m/0'/1/2'/2`, async () => {
			const path = `m/0'/1/2'/2`
			const expected = 0x0F479245FB19A38A1954C5C7C0EBAB2F9BDFD96A17563EF28A6A4B1A2A764EF4n
			const privateKey = await hdWallet.privateKeyFromSeed(seed, path)
			expect(privateKey).toEqual(expected)
		})
		it(`m/0'/1/2'/2/1000000000`, async () => {
			const path = `m/0'/1/2'/2/1000000000`
			const expected = 0x471B76E389E528D6DE6D816857E012C5455051CAD6660850E58372A6C3E6E7C8n
			const privateKey = await hdWallet.privateKeyFromSeed(seed, path)
			expect(privateKey).toEqual(expected)
		})
	})
	describe('4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be', () => {
		// from https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#Test_vector_3
		const seed = 0x4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235ben
		it(`m`, async () => {
			const path = `m`
			const expected = 0x00DDB80B067E0D4993197FE10F2657A844A384589847602D56F0C629C81AAE32n
			const privateKey = await hdWallet.privateKeyFromSeed(seed, path)
			expect(privateKey).toEqual(expected)
		})
		it(`m/0'`, async () => {
			const path = `m/0'`
			const expected = 0x491F7A2EEBC7B57028E0D3FAA0ACDA02E75C33B03C48FB288C41E2EA44E1DAEFn
			const privateKey = await hdWallet.privateKeyFromSeed(seed, path)
			expect(privateKey).toEqual(expected)
		})
	})
})

describe('ethereum', () => {
	it('signs prefixed message', async () => {
		const privateKey = 1n
		const messageToSign = 'hello'
		const signature = await ethereum.mutateAndSign(privateKey, messageToSign)
		expect(signature.r).toEqual(103971450176177714643557042981572514570117585915721523808868249554313735244206n)
		expect(signature.s).toEqual(5259501285923218377719486404094138176021472319928632716132134674704837414442n)
		expect(signature.recoveryParameter).toEqual(0)
	})
	it('signature to selector', async () => {
		const signature = 'transfer(address,uint256)'
		const expected = 0xa9059cbb
		const actual = await ethereum.functionSignatureToSelector(signature)
		expect(actual).toEqual(expected)
	})
	it('private key to address', async () => {
		const privateKey = 0xfae42052f82bed612a724fec3632f325f377120592c75bb78adfcceae6470c5an
		const expected = 0x913da4198e6be1d5f5e4a40d0667f70c0b5430ebn
		const publicKey = await secp256k1.privateKeyToPublicKey(privateKey)
		const address = await ethereum.publicKeyToAddress(publicKey)
		expect(address).toEqual(expected)
	})
	describe('addressToChecksummedString', () => {
		it('all caps 1', async () => {
			const expected = '52908400098527886E0F7030069857D2E4169EE7'
			const input = BigInt(`0x${expected}`)
			const actual = await ethereum.addressToChecksummedString(input)
			expect(actual).toEqual(expected)
		})
		it('all caps 2', async () => {
			const expected = '8617E340B3D01FA5F11F306F4090FD50E238070D'
			const input = BigInt(`0x${expected}`)
			const actual = await ethereum.addressToChecksummedString(input)
			expect(actual).toEqual(expected)
		})
		it('all lower 1', async () => {
			const expected = 'de709f2102306220921060314715629080e2fb77'
			const input = BigInt(`0x${expected}`)
			const actual = await ethereum.addressToChecksummedString(input)
			expect(actual).toEqual(expected)
		})
		it('all lower 2', async () => {
			const expected = '27b1fdb04752bbc536007a920d24acb045561c26'
			const input = BigInt(`0x${expected}`)
			const actual = await ethereum.addressToChecksummedString(input)
			expect(actual).toEqual(expected)
		})
		it('mixed 1', async () => {
			const expected = '5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed'
			const input = BigInt(`0x${expected}`)
			const actual = await ethereum.addressToChecksummedString(input)
			expect(actual).toEqual(expected)
		})
		it('mixed 2', async () => {
			const expected = 'fB6916095ca1df60bB79Ce92cE3Ea74c37c5d359'
			const input = BigInt(`0x${expected}`)
			const actual = await ethereum.addressToChecksummedString(input)
			expect(actual).toEqual(expected)
		})
		it('mixed 3', async () => {
			const expected = 'dbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB'
			const input = BigInt(`0x${expected}`)
			const actual = await ethereum.addressToChecksummedString(input)
			expect(actual).toEqual(expected)
		})
		it('mixed 4', async () => {
			const expected = 'D1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb'
			const input = BigInt(`0x${expected}`)
			const actual = await ethereum.addressToChecksummedString(input)
			expect(actual).toEqual(expected)
		})
		it('leading 0', async () => {
			const expected = '09712a34b13da16436BBeaC6132A7458Be2ecA0A'
			const input = BigInt(0x9712a34b13da16436BBeaC6132A7458Be2ecA0An)
			const actual = await ethereum.addressToChecksummedString(input)
			expect(actual).toEqual(expected)
		})
	})
	describe('validateAddressChecksum', () => {
		describe('valid', () => {
			it('all caps 1', async () => {
				const input = '52908400098527886E0F7030069857D2E4169EE7'
				const isValid = await ethereum.validateAddressChecksum(input)
				expect(isValid).toEqual(true)
			})
			it('all caps 2', async () => {
				const input = '8617E340B3D01FA5F11F306F4090FD50E238070D'
				const isValid = await ethereum.validateAddressChecksum(input)
				expect(isValid).toEqual(true)
			})
			it('all lower 1', async () => {
				const input = 'de709f2102306220921060314715629080e2fb77'
				const isValid = await ethereum.validateAddressChecksum(input)
				expect(isValid).toEqual(true)
			})
			it('all lower 2', async () => {
				const input = '27b1fdb04752bbc536007a920d24acb045561c26'
				const isValid = await ethereum.validateAddressChecksum(input)
				expect(isValid).toEqual(true)
			})
			it('mixed 1', async () => {
				const input = '5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed'
				const isValid = await ethereum.validateAddressChecksum(input)
				expect(isValid).toEqual(true)
			})
			it('mixed 2', async () => {
				const input = 'fB6916095ca1df60bB79Ce92cE3Ea74c37c5d359'
				const isValid = await ethereum.validateAddressChecksum(input)
				expect(isValid).toEqual(true)
			})
			it('mixed 3', async () => {
				const input = 'dbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB'
				const isValid = await ethereum.validateAddressChecksum(input)
				expect(isValid).toEqual(true)
			})
			it('mixed 4', async () => {
				const input = 'D1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb'
				const isValid = await ethereum.validateAddressChecksum(input)
				expect(isValid).toEqual(true)
			})
			it('with 0x prefix', async () => {
				const input = '0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb'
				const isValid = await ethereum.validateAddressChecksum(input)
				expect(isValid).toEqual(true)
			})
			it('leading 0', async () => {
				const input = '0x09712a34b13da16436BBeaC6132A7458Be2ecA0A'
				const isValid = await ethereum.validateAddressChecksum(input)
				expect(isValid).toEqual(true)
			})
		})
		describe('invalid', () => {
			it('non-hex character', async () => {
				const value = '5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeg'
				const isValid = await ethereum.validateAddressChecksum(value)
				expect(isValid).toEqual(false)
			})
			it('too long', async () => {
				const value = '5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed0'
				const isValid = await ethereum.validateAddressChecksum(value)
				expect(isValid).toEqual(false)
			})
			it('too short', async () => {
				const value = '5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAe'
				const isValid = await ethereum.validateAddressChecksum(value)
				expect(isValid).toEqual(false)
			})
			it('all caps 1', async () => {
				const value = '52908400098527886E0F7030069857D2E4169Ee7'
				const isValid = await ethereum.validateAddressChecksum(value)
				expect(isValid).toEqual(false)
			})
			it('all caps 2', async () => {
				const value = '8617E340B3D01FA5f11F306F4090FD50E238070D'
				const isValid = await ethereum.validateAddressChecksum(value)
				expect(isValid).toEqual(false)
			})
			it('all lower 1', async () => {
				const value = 'De709f2102306220921060314715629080e2fb77'
				const isValid = await ethereum.validateAddressChecksum(value)
				expect(isValid).toEqual(false)
			})
			it('all lower 2', async () => {
				const value = '27b1Fdb04752bbc536007a920d24acb045561c26'
				const isValid = await ethereum.validateAddressChecksum(value)
				expect(isValid).toEqual(false)
			})
			it('mixed 1', async () => {
				const value = '5aAeB6053F3E94C9b9A09f33669435E7Ef1BeAed'
				const isValid = await ethereum.validateAddressChecksum(value)
				expect(isValid).toEqual(false)
			})
			it('mixed 2', async () => {
				const value = 'fB6916095ca1df60bb79Ce92cE3Ea74c37c5d359'
				const isValid = await ethereum.validateAddressChecksum(value)
				expect(isValid).toEqual(false)
			})
			it('mixed 3', async () => {
				const value = 'dbF03B407c01E7cd3CBea99509d93f8DDDC8C6FB'
				const isValid = await ethereum.validateAddressChecksum(value)
				expect(isValid).toEqual(false)
			})
			it('mixed 4', async () => {
				const value = 'D1220A0cf47c7B9Be7A2E6BA89F429762e7B9ADb'
				const isValid = await ethereum.validateAddressChecksum(value)
				expect(isValid).toEqual(false)
			})
		})
	})
})

describe('sandbox', () => {
	it('sandbox', async () => {
	})
})

jasmine.execute()

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
