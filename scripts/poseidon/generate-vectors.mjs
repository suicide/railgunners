import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const require = createRequire(import.meta.url);
const enginePackageRoot = path.join(__dirname, 'node_modules', '@railgun-community', 'engine');

const circom = require('@railgun-community/circomlibjs');
const {
  ByteLength,
  ByteUtils,
  getGlobalTreePosition,
  getRailgunTransactionIDFromBigInts,
  getRailgunTxidLeafHash,
} = require('@railgun-community/engine');
const { MERKLE_ZERO_VALUE_BIGINT } = require(
  path.join(enginePackageRoot, 'dist', 'models', 'merkletree-types.js'),
);
const { initPoseidonPromise } = require(
  path.join(enginePackageRoot, 'dist', 'utils', 'poseidon.js'),
);

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const DEFAULT_OUT_DIR = path.join(REPO_ROOT, 'crates', 'railgun-core', 'testdata', 'poseidon');

const CIRCOMLIBJS_SOURCE = {
  package: '@railgun-community/circomlibjs',
  packageVersion: '0.0.8',
  repo: 'https://github.com/Railgun-Community/circomlibjs',
  referencePath: 'src/poseidon_opt.js',
};

const ENGINE_SOURCE = {
  package: '@railgun-community/engine',
  packageVersion: '9.5.4',
  repo: 'https://github.com/Railgun-Community/engine',
  txidPath: 'src/transaction/railgun-txid.ts',
  merkleZeroPath: 'src/models/merkletree-types.ts',
  proofVectorPath: 'src/test/test-vector-poi.json',
};

const ENGINE_PROOF_VECTOR_URL =
  'https://raw.githubusercontent.com/Railgun-Community/engine/main/src/test/test-vector-poi.json';
const BN254_SCALAR_FIELD_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const GLOBAL_TREE_POSITION_TREE = 99_999;
const GLOBAL_TREE_POSITION_INDEX = 99_999;

const CIRCOMLIBJS_CASES = [
  ...[1, 2, 3, 13].map((arity) => ({
    name: `sequential_arity_${arity}`,
    inputs: Array.from({ length: arity }, (_, index) => BigInt(index)),
  })),
  ...Array.from({ length: 13 }, (_, index) => ({
    name: `repeated_one_arity_${index + 1}`,
    inputs: Array.from({ length: index + 1 }, () => 1n),
  })),
  {
    name: 'pair_one_two',
    inputs: [1n, 2n],
  },
  {
    name: 'triple_one_two_three',
    inputs: [1n, 2n, 3n],
  },
  {
    name: 'thirteen_one_through_thirteen',
    inputs: Array.from({ length: 13 }, (_, index) => BigInt(index + 1)),
  },
  {
    name: 'pair_zero_modulus_minus_one',
    inputs: [0n, BN254_SCALAR_FIELD_MODULUS - 1n],
  },
  {
    name: 'triple_one_modulus_minus_one_two',
    inputs: [1n, BN254_SCALAR_FIELD_MODULUS - 1n, 2n],
  },
  {
    name: 'alternating_zero_one_arity_8',
    inputs: Array.from({ length: 8 }, (_, index) => BigInt(index % 2)),
  },
  {
    name: 'powers_of_two_arity_4',
    inputs: [1n, 2n, 4n, 8n],
  },
  {
    name: 'near_modulus_descending_arity_13',
    inputs: Array.from({ length: 13 }, (_, index) => BN254_SCALAR_FIELD_MODULUS - BigInt(index + 1)),
  },
];

const ENGINE_TXID_CASES = [
  {
    name: 'single_nullifier_single_commitment',
    nullifiers: [
      '0x05802951a46d9e999151eb0eb9e4c7c1260b7ee88539011c207dc169c4dd17ee',
    ],
    commitments: [
      '0x007aaf0cbee05066820873170e293e44df6766c29da69ac46fd05d4ff2c0a225',
    ],
    boundParamsHash: '0x0a4e7bed8287c629fd064665543dc71fdc09b0ab9df7d556f24a1f2f9f018dc7',
    utxoTreeIn: 0,
    globalTreePosition: getGlobalTreePosition(99999, 99999),
  },
  {
    name: 'simple_small_values',
    nullifiers: ['0x01', '0x02'],
    commitments: ['0x03', '0x04', '0x05'],
    boundParamsHash: '0x06',
    utxoTreeIn: 0,
    globalTreePosition: getGlobalTreePosition(0, 1),
  },
  {
    name: 'exactly_thirteen_inputs',
    nullifiers: Array.from({ length: 13 }, (_, index) => ByteUtils.nToHex(BigInt(index + 1), ByteLength.UINT_256)),
    commitments: Array.from({ length: 13 }, (_, index) => ByteUtils.nToHex(BigInt(index + 21), ByteLength.UINT_256)),
    boundParamsHash: ByteUtils.nToHex(999n, ByteLength.UINT_256),
    utxoTreeIn: 7,
    globalTreePosition: getGlobalTreePosition(2, 9),
  },
  {
    name: 'empty_inputs',
    nullifiers: [],
    commitments: [],
    boundParamsHash: ByteUtils.nToHex(42n, ByteLength.UINT_256),
    utxoTreeIn: 3,
    globalTreePosition: getGlobalTreePosition(4, 5),
  },
  {
    name: 'twelve_nullifiers_empty_commitments',
    nullifiers: Array.from({ length: 12 }, (_, index) => ByteUtils.nToHex(BigInt(index + 101), ByteLength.UINT_256)),
    commitments: [],
    boundParamsHash: ByteUtils.nToHex(123456789n, ByteLength.UINT_256),
    utxoTreeIn: 11,
    globalTreePosition: getGlobalTreePosition(6, 12),
  },
  {
    name: 'empty_nullifiers_twelve_commitments',
    nullifiers: [],
    commitments: Array.from({ length: 12 }, (_, index) => ByteUtils.nToHex(BigInt(index + 201), ByteLength.UINT_256)),
    boundParamsHash: ByteUtils.nToHex(987654321n, ByteLength.UINT_256),
    utxoTreeIn: 12,
    globalTreePosition: getGlobalTreePosition(8, 1),
  },
  {
    name: 'near_modulus_values',
    nullifiers: [
      ByteUtils.nToHex(BN254_SCALAR_FIELD_MODULUS - 1n, ByteLength.UINT_256),
      ByteUtils.nToHex(BN254_SCALAR_FIELD_MODULUS + 5n, ByteLength.UINT_256),
    ],
    commitments: [
      ByteUtils.nToHex(BN254_SCALAR_FIELD_MODULUS - 2n, ByteLength.UINT_256),
      ByteUtils.nToHex(BN254_SCALAR_FIELD_MODULUS + 7n, ByteLength.UINT_256),
      ByteUtils.nToHex((BN254_SCALAR_FIELD_MODULUS * 2n) + 9n, ByteLength.UINT_256),
    ],
    boundParamsHash: ByteUtils.nToHex(BN254_SCALAR_FIELD_MODULUS + 11n, ByteLength.UINT_256),
    utxoTreeIn: 255,
    globalTreePosition: getGlobalTreePosition(1234, 5678),
  },
];

await initPoseidonPromise;

const args = parseArgs(process.argv.slice(2));
const outDir = path.resolve(REPO_ROOT, args.outDir ?? DEFAULT_OUT_DIR);
const only = args.only ?? 'all';

await mkdir(outDir, { recursive: true });

const engineMerkleProofFixture =
  only === 'all' || only === 'engine' ? await generateEngineMerkleProofFixture() : null;

const outputs = [];
if (only === 'all' || only === 'circomlibjs') {
  outputs.push([
    path.join(outDir, 'circomlibjs.json'),
    JSON.stringify(generateCircomlibjsVectors(), null, 2) + '\n',
  ]);
}

if (only === 'all' || only === 'engine') {
  outputs.push([
    path.join(outDir, 'engine-txid.json'),
    JSON.stringify(generateEngineTxidVectors(), null, 2) + '\n',
  ]);
  outputs.push([
    path.join(outDir, 'engine-txid-merkle-proof.json'),
    JSON.stringify(engineMerkleProofFixture, null, 2) + '\n',
  ]);
}

let allMatched = true;
for (const [filePath, nextContent] of outputs) {
  if (args.check) {
    const existingContent = await readExisting(filePath);
    if (existingContent !== nextContent) {
      allMatched = false;
      process.stderr.write(`Mismatch: ${path.relative(REPO_ROOT, filePath)}\n`);
    }
  } else {
    await writeFile(filePath, nextContent, 'utf8');
    process.stdout.write(`Wrote ${path.relative(REPO_ROOT, filePath)}\n`);
  }
}

if (args.check && !allMatched) {
  process.exitCode = 1;
}

function generateCircomlibjsVectors() {
  return {
    source: CIRCOMLIBJS_SOURCE,
    cases: CIRCOMLIBJS_CASES.map((testCase) => {
      const output = circom.poseidon(testCase.inputs);
      return {
        name: testCase.name,
        arity: testCase.inputs.length,
        inputsDecimal: testCase.inputs.map(toDecimal),
        inputsHex: testCase.inputs.map(toHex),
        outputDecimal: toDecimal(output),
        outputHex: toHex(output),
      };
    }),
  };
}

function generateEngineTxidVectors() {
  return {
    source: ENGINE_SOURCE,
    canonicalMerkleZeroDecimal: toDecimal(MERKLE_ZERO_VALUE_BIGINT),
    canonicalMerkleZeroHex: toHex(MERKLE_ZERO_VALUE_BIGINT),
    cases: ENGINE_TXID_CASES.map((testCase) => {
      const nullifiers = testCase.nullifiers.map(ByteUtils.hexToBigInt);
      const commitments = testCase.commitments.map(ByteUtils.hexToBigInt);
      const boundParamsHash = ByteUtils.hexToBigInt(testCase.boundParamsHash);

      const nullifiersPadded = padToThirteen(nullifiers);
      const commitmentsPadded = padToThirteen(commitments);
      const nullifiersHash = circom.poseidon(nullifiersPadded);
      const commitmentsHash = circom.poseidon(commitmentsPadded);
      const railgunTxid = getRailgunTransactionIDFromBigInts(
        nullifiers,
        commitments,
        boundParamsHash,
      );
      const txidLeafHash = ByteUtils.hexToBigInt(
        getRailgunTxidLeafHash(
          railgunTxid,
          BigInt(testCase.utxoTreeIn),
          testCase.globalTreePosition,
        ),
      );

      return {
        name: testCase.name,
        nullifiersHex: testCase.nullifiers,
        commitmentsHex: testCase.commitments,
        boundParamsHashHex: toHex(boundParamsHash),
        nullifiersPaddedHex: nullifiersPadded.map(toHex),
        commitmentsPaddedHex: commitmentsPadded.map(toHex),
        nullifiersHashHex: toHex(nullifiersHash),
        commitmentsHashHex: toHex(commitmentsHash),
        railgunTxidHex: toHex(railgunTxid),
        utxoTreeIn: testCase.utxoTreeIn,
        globalTreePositionDecimal: toDecimal(testCase.globalTreePosition),
        globalTreePositionHex: toHex(testCase.globalTreePosition),
        txidLeafHashHex: toHex(txidLeafHash),
      };
    }),
    txidLeafReferenceCase: {
      railgunTxidHex: toHex(12157249116530410877712851712509084797672039320300907005218073634829938454808n),
      utxoTreeIn: 0,
      globalTreePositionDecimal: toDecimal(getGlobalTreePosition(GLOBAL_TREE_POSITION_TREE, GLOBAL_TREE_POSITION_INDEX)),
      globalTreePositionHex: toHex(getGlobalTreePosition(GLOBAL_TREE_POSITION_TREE, GLOBAL_TREE_POSITION_INDEX)),
      txidLeafHashHex: getRailgunTxidLeafHash(
        12157249116530410877712851712509084797672039320300907005218073634829938454808n,
        0n,
        getGlobalTreePosition(GLOBAL_TREE_POSITION_TREE, GLOBAL_TREE_POSITION_INDEX),
      ),
    },
  };
}

async function generateEngineMerkleProofFixture() {
  const response = await fetch(ENGINE_PROOF_VECTOR_URL);
  if (!response.ok) {
    throw new Error(`failed to fetch engine proof vector: ${response.status} ${response.statusText}`);
  }

  const vector = await response.json();
  return {
    source: {
      package: ENGINE_SOURCE.package,
      packageVersion: ENGINE_SOURCE.packageVersion,
      repo: ENGINE_SOURCE.repo,
      referencePath: ENGINE_SOURCE.proofVectorPath,
      rawUrl: ENGINE_PROOF_VECTOR_URL,
    },
    case: {
      name: 'single_nullifier_single_commitment_proof',
      railgunTxidHex: strip0x(vector.railgunTxidIfHasUnshield),
      utxoTreeIn: Number(vector.utxoTreeIn),
      globalTreePosition: Number(vector.utxoBatchGlobalStartPositionOut),
      merkleRootHex: strip0x(vector.anyRailgunTxidMerklerootAfterTransaction),
      indicesHex: strip0x(vector.railgunTxidMerkleProofIndices),
      pathElementsHex: vector.railgunTxidMerkleProofPathElements.map(strip0x),
    },
  };
}

function padToThirteen(values) {
  const padded = [...values];
  while (padded.length < 13) {
    padded.push(MERKLE_ZERO_VALUE_BIGINT);
  }
  return padded;
}

function toDecimal(value) {
  return value.toString(10);
}

function toHex(value) {
  return ByteUtils.nToHex(value, ByteLength.UINT_256);
}

function strip0x(value) {
  return value.startsWith('0x') ? value.slice(2) : value;
}

function parseArgs(argv) {
  const parsed = {
    check: false,
    outDir: undefined,
    only: undefined,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--check') {
      parsed.check = true;
    } else if (arg === '--out-dir') {
      parsed.outDir = argv[index + 1];
      index += 1;
    } else if (arg === '--only') {
      parsed.only = argv[index + 1];
      index += 1;
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }

  if (parsed.only && !['all', 'circomlibjs', 'engine'].includes(parsed.only)) {
    throw new Error(`Unsupported --only value: ${parsed.only}`);
  }

  return parsed;
}

async function readExisting(filePath) {
  try {
    return await readFile(filePath, 'utf8');
  } catch (error) {
    if (error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT') {
      return null;
    }
    throw error;
  }
}
