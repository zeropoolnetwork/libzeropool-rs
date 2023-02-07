use byteorder::{LittleEndian, ReadBytesExt};
use libzeropool_rs::{
    delegated_deposit::{
        FullDelegatedDeposit, DELEGATED_DEPOSIT_MAGIC, FULL_DELEGATED_DEPOSIT_SIZE,
    },
    keys::Keys,
    libzeropool::{
        fawkes_crypto::ff_uint::{Num, NumRepr, Uint},
        native::{
            account::Account,
            cipher,
            key::{self, derive_key_p_d},
            note::Note,
        },
    },
    merkle::Hash,
};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use wasm_bindgen::{prelude::*, JsCast};

use crate::{Fr, Fs, IndexedNote, IndexedTx, ParseTxsResult, PoolParams, POOL_PARAMS};

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct StateUpdate {
    #[serde(rename = "newLeafs")]
    pub new_leafs: Vec<(u64, Vec<Hash<Fr>>)>,
    #[serde(rename = "newCommitments")]
    pub new_commitments: Vec<(u64, Hash<Fr>)>,
    #[serde(rename = "newAccounts")]
    pub new_accounts: Vec<(u64, Account<Fr>)>,
    #[serde(rename = "newNotes")]
    pub new_notes: Vec<Vec<(u64, Note<Fr>)>>,
}

#[derive(Serialize, Deserialize, Clone, Default)]
struct DecMemo {
    index: u64,
    acc: Option<Account<Fr>>,
    #[serde(rename = "inNotes")]
    in_notes: Vec<IndexedNote>,
    #[serde(rename = "outNotes")]
    out_notes: Vec<IndexedNote>,
    #[serde(rename = "txHash")]
    tx_hash: Option<String>,
}

#[derive(Serialize, Default)]
struct ParseResult {
    #[serde(rename = "decryptedMemos")]
    decrypted_memos: Vec<DecMemo>,
    #[serde(rename = "stateUpdate")]
    state_update: StateUpdate,
}

#[wasm_bindgen]
pub struct TxParser {
    #[wasm_bindgen(skip)]
    pub params: PoolParams,
}

#[wasm_bindgen]
impl TxParser {
    #[wasm_bindgen(js_name = "new")]
    pub fn new() -> Result<TxParser, JsValue> {
        Ok(TxParser {
            params: POOL_PARAMS.clone(),
        })
    }

    #[wasm_bindgen(js_name = "parseTxs")]
    pub fn parse_txs(&self, sk: &[u8], txs: &JsValue) -> Result<ParseTxsResult, JsValue> {
        let sk = Num::<Fs>::from_uint(NumRepr(Uint::from_little_endian(sk)))
            .ok_or_else(|| js_err!("Invalid spending key"))?;
        let params = &self.params;
        let eta = Keys::derive(sk, params).eta;

        let txs: Vec<IndexedTx> = txs.into_serde().map_err(|err| js_err!(&err.to_string()))?;
        let parse_results: Vec<_> = txs
            .into_par_iter()
            .map(|tx| -> ParseResult {
                let IndexedTx {
                    index,
                    memo,
                    commitment,
                } = tx;
                let memo = hex::decode(memo).unwrap();
                let commitment = hex::decode(commitment).unwrap();

                // Special case: transaction contains delegated deposits
                if &memo[0..4] == &DELEGATED_DEPOSIT_MAGIC {
                    let account_hash =
                        Num::from_uint_reduced(NumRepr(Uint::from_big_endian(&memo[4..36])));
                    let num_deposits = (memo.len() - DELEGATED_DEPOSIT_MAGIC.len() - 32)
                        / FULL_DELEGATED_DEPOSIT_SIZE;

                    let delegated_deposits = (&memo[36..])
                        .chunks(FULL_DELEGATED_DEPOSIT_SIZE)
                        .take(num_deposits)
                        .map(|data| std::io::Result::Ok(FullDelegatedDeposit::read(data)?))
                        .collect::<Result<Vec<_>, _>>()
                        .unwrap();

                    let in_notes_indexed = delegated_deposits
                        .iter()
                        .enumerate()
                        .filter_map(|(i, d)| {
                            let p_d = derive_key_p_d(d.receiver_d.to_num(), eta, &self.params).x;
                            if d.receiver_p == p_d {
                                Some(IndexedNote {
                                    index: index + 1 + (i as u64), // FIXME: offset index
                                    note: d.to_delegated_deposit().to_note(),
                                })
                            } else {
                                None
                            }
                        })
                        .collect::<Vec<_>>();

                    let in_notes = in_notes_indexed
                        .iter()
                        .map(|n| (n.index, n.note.clone()))
                        .collect();

                    let hashes = [account_hash]
                        .iter()
                        .copied()
                        .chain(
                            delegated_deposits
                                .iter()
                                .map(|d| d.to_delegated_deposit().to_note().hash(&self.params)),
                        )
                        .collect();

                    let parse_result = ParseResult {
                        decrypted_memos: vec![DecMemo {
                            index,
                            in_notes: in_notes_indexed,
                            ..Default::default()
                        }],
                        state_update: StateUpdate {
                            new_leafs: vec![(index, hashes)],
                            new_notes: vec![in_notes],
                            ..Default::default()
                        },
                    };

                    return parse_result;
                }

                let num_hashes = (&memo[0..4]).read_u32::<LittleEndian>().unwrap();
                let hashes: Vec<_> = (&memo[4..])
                    .chunks(32)
                    .take(num_hashes as usize)
                    .map(|bytes| Num::from_uint_reduced(NumRepr(Uint::from_little_endian(bytes))))
                    .collect();

                let pair = cipher::decrypt_out(eta, &memo.clone(), params);

                match pair {
                    Some((account, notes)) => {
                        let mut in_notes = Vec::new();
                        let mut out_notes = Vec::new();
                        notes.into_iter().enumerate().for_each(|(i, note)| {
                            out_notes.push((index + 1 + (i as u64), note));

                            if note.p_d == key::derive_key_p_d(note.d.to_num(), eta, params).x {
                                in_notes.push((index + 1 + (i as u64), note));
                            }
                        });

                        ParseResult {
                            decrypted_memos: vec![DecMemo {
                                index,
                                acc: Some(account),
                                in_notes: in_notes
                                    .clone()
                                    .into_iter()
                                    .map(|(index, note)| IndexedNote { index, note })
                                    .collect(),
                                out_notes: out_notes
                                    .into_iter()
                                    .map(|(index, note)| IndexedNote { index, note })
                                    .collect(),
                                ..Default::default()
                            }],
                            state_update: StateUpdate {
                                new_leafs: vec![(index, hashes)],
                                new_accounts: vec![(index, account)],
                                new_notes: vec![in_notes],
                                ..Default::default()
                            },
                        }
                    }
                    None => {
                        let in_notes: Vec<(_, _)> = cipher::decrypt_in(eta, &memo, params)
                            .into_iter()
                            .enumerate()
                            .filter_map(|(i, note)| match note {
                                Some(note)
                                    if note.p_d
                                        == key::derive_key_p_d(note.d.to_num(), eta, params).x =>
                                {
                                    Some((index + 1 + (i as u64), note))
                                }
                                _ => None,
                            })
                            .collect();

                        if !in_notes.is_empty() {
                            ParseResult {
                                decrypted_memos: vec![DecMemo {
                                    index,
                                    in_notes: in_notes
                                        .clone()
                                        .into_iter()
                                        .map(|(index, note)| IndexedNote { index, note })
                                        .collect(),
                                    ..Default::default()
                                }],
                                state_update: StateUpdate {
                                    new_leafs: vec![(index, hashes)],
                                    new_notes: vec![in_notes],
                                    ..Default::default()
                                },
                            }
                        } else {
                            ParseResult {
                                state_update: StateUpdate {
                                    new_commitments: vec![(
                                        index,
                                        Num::from_uint_reduced(NumRepr(Uint::from_big_endian(
                                            &commitment,
                                        ))),
                                    )],
                                    ..Default::default()
                                },
                                ..Default::default()
                            }
                        }
                    }
                }
            })
            .collect();

        let mut parse_result =
            parse_results
                .into_iter()
                .fold(Default::default(), |acc: ParseResult, parse_result| {
                    ParseResult {
                        decrypted_memos: vec![acc.decrypted_memos, parse_result.decrypted_memos]
                            .concat(),
                        state_update: StateUpdate {
                            new_leafs: vec![
                                acc.state_update.new_leafs,
                                parse_result.state_update.new_leafs,
                            ]
                            .concat(),
                            new_commitments: vec![
                                acc.state_update.new_commitments,
                                parse_result.state_update.new_commitments,
                            ]
                            .concat(),
                            new_accounts: vec![
                                acc.state_update.new_accounts,
                                parse_result.state_update.new_accounts,
                            ]
                            .concat(),
                            new_notes: vec![
                                acc.state_update.new_notes,
                                parse_result.state_update.new_notes,
                            ]
                            .concat(),
                        },
                    }
                });

        parse_result
            .decrypted_memos
            .sort_by(|a, b| a.index.cmp(&b.index));

        let parse_result = serde_wasm_bindgen::to_value(&parse_result)
            .unwrap()
            .unchecked_into::<ParseTxsResult>();
        Ok(parse_result)
    }
}
