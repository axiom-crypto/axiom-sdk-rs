export const axiomDocs = "// Generated by dts-bundle-generator v8.0.1\n\n\ndeclare enum HeaderField {\n\tParentHash = 0,\n\tSha3Uncles = 1,\n\tMiner = 2,\n\tStateRoot = 3,\n\tTransactionsRoot = 4,\n\tReceiptsRoot = 5,\n\tDifficulty = 7,\n\tNumber = 8,\n\tGasLimit = 9,\n\tGasUsed = 10,\n\tTimestamp = 11,\n\tExtraData = 12,\n\tMixHash = 13,\n\tNonce = 14,\n\tBaseFeePerGas = 15,\n\tWithdrawalsRoot = 16,\n\tHash = 17,\n\tSize = 18\n}\ndeclare enum AccountField {\n\tNonce = 0,\n\tBalance = 1,\n\tStorageRoot = 2,\n\tCodeHash = 3\n}\ndeclare enum TxField {\n\tChainId = 0,\n\tNonce = 1,\n\tMaxPriorityFeePerGas = 2,\n\tMaxFeePerGas = 3,\n\tGasLimit = 4,\n\tTo = 5,\n\tValue = 6,\n\tData = 7,\n\tGasPrice = 8,\n\tv = 9,\n\tr = 10,\n\ts = 11\n}\ndeclare enum ReceiptField {\n\tStatus = 0,\n\tPostState = 1,\n\tCumulativeGas = 2,\n\tLogs = 4\n}\ndeclare class CircuitValue256 {\n\tprivate _value;\n\tprivate circuitValue;\n\tprivate circuit;\n\tconstructor(circuit: Halo2Wasm, { value, hi, lo }: {\n\t\tvalue?: bigint | string | number;\n\t\thi?: CircuitValue;\n\t\tlo?: CircuitValue;\n\t});\n\thi(): CircuitValue;\n\tlo(): CircuitValue;\n\thex(): string;\n\tvalue(): bigint;\n\ttoCircuitValue(): CircuitValue;\n}\ntype AccountEnumKeys = Uncapitalize<keyof typeof AccountField>;\ntype AccountEnumKeyFields = {\n\t[key in AccountEnumKeys]: () => Promise<CircuitValue256>;\n};\ninterface Account extends AccountEnumKeyFields {\n}\n/**\n * Represents a log entry in a receipt.\n */\ninterface Log {\n\t/**\n\t * Retrieves the value of a specific topic in the log entry.\n\t *\n\t * @param topicIdx The index of the topic.\n\t * @param eventSchema The event schema.\n\t * @returns A `CircuitValue` representing the value of the topic.\n\t */\n\ttopic: (topicIdx: RawCircuitInput | CircuitValue, eventSchema?: string | CircuitValue256) => Promise<CircuitValue256>;\n\t/**\n\t * Retrieves the address a log was emitted from\n\t *\n\t * @returns A `CircuitValue` representing `Log.address`.\n\t */\n\taddress: () => Promise<CircuitValue256>;\n\t/**\n\t * Retrieves a 32 byte chunk of a log's data field.\n\t *\n\t * @param dataIdx The index of the 32 byte chunk\n\t * @param eventSchema The event schema.\n\t * @returns A `CircuitValue256` representing the 32 byte chunk of the log data.\n\t */\n\tdata: (dataIdx: CircuitValue | RawCircuitInput, eventSchema?: string | CircuitValue256) => Promise<CircuitValue256>;\n}\ntype ReceiptEnumKeys = Uncapitalize<keyof typeof ReceiptField>;\ntype ReceiptEnumKeyFieldsUnfiltered = {\n\t[key in ReceiptEnumKeys]: () => Promise<CircuitValue256>;\n};\ntype ReceiptEnumKeyFields = Omit<ReceiptEnumKeyFieldsUnfiltered, \"logs\" | \"postState\" | \"logsBloom\">;\ndeclare enum SpecialReceiptField {\n\tTxType = 51,\n\tBlockNumber = 52,\n\tTxIdx = 53\n}\ntype SpecialReceiptKeys = Uncapitalize<keyof typeof SpecialReceiptField>;\ntype SpecialReceiptKeyFields = {\n\t[key in SpecialReceiptKeys]: () => Promise<CircuitValue256>;\n};\n/**\n * Represents a receipt.\n */\ninterface Receipt extends ReceiptEnumKeyFields, SpecialReceiptKeyFields {\n\t/**\n\t * Retrieves a log entry in the receipt.\n\t *\n\t * @param logIdx The index of the log entry.\n\t * @returns A `Log` object representing the log entry.\n\t */\n\tlog: (logIdx: RawCircuitInput | CircuitValue) => Log;\n\t/**\n\t * Retrieves a 32 byte chunk of the logs bloom.\n\t *\n\t * @param logsBloomIdx The index of the 32 byte chunk in [0,8)\n\t * @returns A `CircuitValue256` representing the 32 byte chunk of the logs bloom.\n\t */\n\tlogsBloom: (logsBloomIdx: RawCircuitInput) => Promise<CircuitValue256>;\n}\ntype HeaderEnumKeys = Uncapitalize<keyof typeof HeaderField>;\ntype HeaderEnumKeyFieldsUnfiltered = {\n\t[key in HeaderEnumKeys]: () => Promise<CircuitValue256>;\n};\ntype HeaderEnumKeyFields = Omit<HeaderEnumKeyFieldsUnfiltered, \"logsBloom\">;\ninterface Header extends HeaderEnumKeyFields {\n\t/**\n\t * Retrieves a 32 byte chunk of the logs bloom.\n\t *\n\t * @param logsBloomIdx The index of the 32 byte chunk in [0,8)\n\t * @returns A `CircuitValue256` in representing the 32 byte chunk of the logs bloom.\n\t */\n\tlogsBloom: (logsBloomIdx: RawCircuitInput) => Promise<CircuitValue256>;\n}\n/**\n * Represents the storage of a contract.\n */\ninterface Storage {\n\t/**\n\t * Retrieves the value stored at a specific slot in the contract's storage.\n\t *\n\t * @param slot - The slot to retrieve the value from.\n\t * @returns A `CircuitValue` representing the value stored at the slot.\n\t */\n\tslot: (slot: RawCircuitInput | CircuitValue256 | CircuitValue) => Promise<CircuitValue256>;\n}\ndeclare enum SpecialTxFields {\n\tType = 51,\n\tBlockNumber = 52,\n\tTxIdx = 53,\n\tFunctionSelector = 54,\n}\ntype SpecialTxKeys = Uncapitalize<keyof typeof SpecialTxFields>;\ntype SpecialTxKeyFields = {\n\t[key in SpecialTxKeys]: () => Promise<CircuitValue256>;\n};\ntype TxEnumKeys = Uncapitalize<keyof typeof TxField>;\ntype TxEnumKeyFields = {\n\t[key in TxEnumKeys]: () => Promise<CircuitValue256>;\n};\ninterface BaseTx extends TxEnumKeyFields {\n}\ninterface SpecialTx extends SpecialTxKeyFields {\n}\ninterface Tx extends BaseTx, SpecialTx {\n\t/**\n\t * Retrieves a 32 byte chunk of the transaction calldata.\n\t *\n\t * @param calldataIdx The index of the 32 byte chunk\n\t * @returns A `CircuitValue256` in representing the 32 byte chunk of the tx calldata.\n\t */\n\tcalldata: (calldataIdx: CircuitValue | RawCircuitInput) => Promise<CircuitValue256>;\n\t/**\n\t * Retrieves a 32 byte chunk of a contract deployment's transaction data.\n\t *\n\t * @param contractDataIdx The index of the 32 byte chunk\n\t * @returns A `CircuitValue256` in representing the 32 byte chunk of the contract deploy data.\n\t */\n\tcontractData: (contractDataIdx: CircuitValue | RawCircuitInput) => Promise<CircuitValue256>;\n}\ninterface SolidityMapping {\n\t/**\n\t * Retrieves the value of a specific key in the mapping.\n\t *\n\t * @param key The key of the mapping.\n\t * @returns A `CircuitValue` representing the value of the key in the mapping.\n\t */\n\tkey: (key: RawCircuitInput | CircuitValue256 | CircuitValue) => Promise<CircuitValue256>;\n\t/**\n\t * Retrieves the value of a nested mapping at a specific depth and with specific keys.\n\t *\n\t * @param mappingDepth The depth of the nested mapping.\n\t * @param keys The keys to access the nested mapping.\n\t * @returns A `CircuitValue` representing the value of the nested mapping.\n\t */\n\tnested: (keys: (RawCircuitInput | CircuitValue256 | CircuitValue)[]) => Promise<CircuitValue256>;\n}\ntype RawCircuitInput = string | number | bigint;\n/**\n * Retrieves the account information for a specific block and address.\n *\n * @param blockNumber The block number.\n * @param address The address of the account.\n * @returns An `Account` object to fetch individual account fields.\n */\ndeclare const getAccount: (blockNumber: number | CircuitValue, address: string | CircuitValue) => Readonly<Account>;\n/**\n * Retrieves the receipt information for a specific transaction hash.\n *\n * @param blockNumber The block number\n * @param txIdx The transaction index in the block\n * @returns A `Receipt` object to fetch individual receipt fields.\n */\ndeclare const getReceipt: (blockNumber: number | CircuitValue, txIdx: number | CircuitValue) => Readonly<Receipt>;\n/**\n * Retrieves the storage information for a specific block and address.\n *\n * @param blockNumber The block number.\n * @param address The address of the contract.\n * @returns A `Storage` object to fetch individual storage slots.\n */\ndeclare const getStorage: (blockNumber: number | CircuitValue, address: string | CircuitValue) => Readonly<Storage>;\n/**\n * Retrieves the transaction information for a specific transaction hash.\n *\n * @param blockNumber The block number\n * @param txIdx The transaction index in the block\n * @returns A `Tx` object to fetch individual transaction fields.\n */\ndeclare const getTx: (blockNumber: number | CircuitValue, txIdx: number | CircuitValue) => Readonly<Tx>;\n/**\n * Retrieves the header information for a specific block number.\n *\n * @param blockNumber The block number.\n * @returns A `Header` object to fetch individual header fields.\n */\ndeclare const getHeader: (blockNumber: number | CircuitValue) => Readonly<Header>;\n/**\n * Retrieves the solidity mapping information for a specific block, address, and slot.\n *\n * @param blockNumber The block number.\n * @param address The address of the contract.\n * @param slot The slot of the mapping.\n * @returns A `SolidityMapping` object to fetch individual mapping slots.\n */\ndeclare const getSolidityMapping: (blockNumber: number | CircuitValue, address: string | CircuitValue, slot: number | bigint | string | CircuitValue256 | CircuitValue) => Readonly<SolidityMapping>;\n/**\n * Creates a `CircuitValue256` from a hi-lo `CircuitValue` pair.\n * \n * @param hi The hi `CircuitValue`.\n * @param lo The lo `CircuitValue`.\n * @returns A `CircuitValue256` object\n */\ndeclare const getCircuitValue256FromHiLo: (hi: CircuitValue, lo: CircuitValue) => CircuitValue256;\n/**\n * Creates a `CircuitValue256` from a `RawCircuitInput`.\n * \n * @param a The raw circuit input.\n * @returns A `CircuitValue256` witness object\n */\ndeclare const getCircuitValue256: (a: RawCircuitInput) => CircuitValue256;\n/**\n * Adds a circuit value to the callback.\n *\n * @param a The circuit value to add to the callback.\n */\ndeclare const addToCallback: (a: CircuitValue | CircuitValue256) => void;";