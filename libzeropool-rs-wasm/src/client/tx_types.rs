use crate::{
    Fr, IDepositData, IDepositPermittableData, IMultiDepositData, IMultiDepositPermittableData,
    IMultiTransferData, IMultiWithdrawData, ITransferData, IWithdrawData,
};
use libzeropool_rs::client::{TokenAmount, TxOutput, TxType as NativeTxType};
use serde::Deserialize;
use wasm_bindgen::prelude::*;

#[allow(clippy::manual_non_exhaustive)]
#[wasm_bindgen]
pub enum TxType {
    Transfer = "transfer",
    Deposit = "deposit",
    DepositPermittable = "deposit_permittable",
    Withdraw = "withdraw",
}

pub trait JsTxType {
    fn to_native(&self) -> Result<NativeTxType<Fr>, JsValue>;
}

pub trait JsMultiTxType {
    fn to_native_array(&self) -> Result<Vec<NativeTxType<Fr>>, JsValue>;
}

#[wasm_bindgen]
#[derive(Deserialize)]
pub struct TxBaseFields {
    fee: TokenAmount<Fr>,
    data: Option<Vec<u8>>,
}

#[wasm_bindgen]
#[derive(Deserialize)]
pub struct DepositData {
    #[serde(flatten)]
    base_fields: TxBaseFields,
    amount: TokenAmount<Fr>,
    outputs: Option<Vec<Output>>,
}

impl JsTxType for IDepositData {
    fn to_native(&self) -> Result<NativeTxType<Fr>, JsValue> {
        let DepositData {
            base_fields,
            amount,
            outputs,
        } = serde_wasm_bindgen::from_value(self.into())?;

        let outputs = outputs
            .map(|outputs| {
                outputs
                    .into_iter()
                    .map(|out| TxOutput {
                        to: out.to,
                        amount: out.amount,
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        Ok(NativeTxType::Deposit(
            base_fields.fee,
            base_fields.data.unwrap_or_default(),
            amount,
            outputs,
        ))
    }
}

impl JsMultiTxType for IMultiDepositData {
    fn to_native_array(&self) -> Result<Vec<NativeTxType<Fr>>, JsValue> {
        let array: Vec<DepositData> = serde_wasm_bindgen::from_value(self.into())?;

        let tx_array = array
            .into_iter()
            .map(|tx| {
                let outputs = tx
                    .outputs
                    .map(|outputs| {
                        outputs
                            .into_iter()
                            .map(|out| TxOutput {
                                to: out.to,
                                amount: out.amount,
                            })
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();

                NativeTxType::Deposit(
                    tx.base_fields.fee,
                    tx.base_fields.data.unwrap_or_default(),
                    tx.amount,
                    outputs,
                )
            })
            .collect();

        Ok(tx_array)
    }
}

#[wasm_bindgen]
#[derive(Deserialize)]
pub struct DepositPermittableData {
    #[serde(flatten)]
    base_fields: TxBaseFields,
    amount: TokenAmount<Fr>,
    deadline: String,
    holder: Vec<u8>,
    outputs: Option<Vec<Output>>,
}

impl JsTxType for IDepositPermittableData {
    fn to_native(&self) -> Result<NativeTxType<Fr>, JsValue> {
        let DepositPermittableData {
            base_fields,
            amount,
            deadline,
            holder,
            outputs,
        } = serde_wasm_bindgen::from_value(self.into())?;

        let outputs = outputs
            .map(|outputs| {
                outputs
                    .into_iter()
                    .map(|out| TxOutput {
                        to: out.to,
                        amount: out.amount,
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        Ok(NativeTxType::DepositPermittable(
            base_fields.fee,
            base_fields.data.unwrap_or_default(),
            amount,
            deadline.parse::<u64>().unwrap_or(0),
            holder,
            outputs,
        ))
    }
}

impl JsMultiTxType for IMultiDepositPermittableData {
    fn to_native_array(&self) -> Result<Vec<NativeTxType<Fr>>, JsValue> {
        let array: Vec<DepositPermittableData> = serde_wasm_bindgen::from_value(self.into())?;

        let tx_array = array
            .into_iter()
            .map(|tx| {
                let outputs = tx
                    .outputs
                    .map(|outputs| {
                        outputs
                            .into_iter()
                            .map(|out| TxOutput {
                                to: out.to,
                                amount: out.amount,
                            })
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                NativeTxType::DepositPermittable(
                    tx.base_fields.fee,
                    tx.base_fields.data.unwrap_or_default(),
                    tx.amount,
                    tx.deadline.parse::<u64>().unwrap_or(0),
                    tx.holder,
                    outputs,
                )
            })
            .collect();

        Ok(tx_array)
    }
}

#[derive(Deserialize)]
pub struct Output {
    to: String,
    amount: TokenAmount<Fr>,
}

#[wasm_bindgen]
#[derive(Deserialize)]
pub struct TransferData {
    #[serde(flatten)]
    base_fields: TxBaseFields,
    outputs: Vec<Output>,
}

impl JsTxType for ITransferData {
    fn to_native(&self) -> Result<NativeTxType<Fr>, JsValue> {
        let TransferData {
            base_fields,
            outputs,
        } = serde_wasm_bindgen::from_value(self.into())?;

        let outputs = outputs
            .into_iter()
            .map(|out| TxOutput {
                to: out.to,
                amount: out.amount,
            })
            .collect::<Vec<_>>();

        Ok(NativeTxType::Transfer(
            base_fields.fee,
            base_fields.data.unwrap_or_default(),
            outputs,
        ))
    }
}

impl JsMultiTxType for IMultiTransferData {
    fn to_native_array(&self) -> Result<Vec<NativeTxType<Fr>>, JsValue> {
        let array: Vec<TransferData> = serde_wasm_bindgen::from_value(self.into())?;

        let tx_array = array
            .into_iter()
            .map(|tx| {
                let outputs = tx
                    .outputs
                    .into_iter()
                    .map(|out| TxOutput {
                        to: out.to,
                        amount: out.amount,
                    })
                    .collect::<Vec<_>>();

                NativeTxType::Transfer(
                    tx.base_fields.fee,
                    tx.base_fields.data.unwrap_or_default(),
                    outputs,
                )
            })
            .collect();

        Ok(tx_array)
    }
}

#[wasm_bindgen]
#[derive(Deserialize)]
pub struct WithdrawData {
    #[serde(flatten)]
    base_fields: TxBaseFields,
    amount: TokenAmount<Fr>,
    to: Vec<u8>,
    native_amount: TokenAmount<Fr>,
    energy_amount: TokenAmount<Fr>,
}

impl JsTxType for IWithdrawData {
    fn to_native(&self) -> Result<NativeTxType<Fr>, JsValue> {
        let WithdrawData {
            base_fields,
            amount,
            to,
            native_amount,
            energy_amount,
        } = serde_wasm_bindgen::from_value(self.into())?;

        Ok(NativeTxType::Withdraw(
            base_fields.fee,
            base_fields.data.unwrap_or_default(),
            amount,
            to,
            native_amount,
            energy_amount,
        ))
    }
}

impl JsMultiTxType for IMultiWithdrawData {
    fn to_native_array(&self) -> Result<Vec<NativeTxType<Fr>>, JsValue> {
        let array: Vec<WithdrawData> = serde_wasm_bindgen::from_value(self.into())?;

        let tx_array = array
            .into_iter()
            .map(|tx| {
                NativeTxType::Withdraw(
                    tx.base_fields.fee,
                    tx.base_fields.data.unwrap_or_default(),
                    tx.amount,
                    tx.to,
                    tx.native_amount,
                    tx.energy_amount,
                )
            })
            .collect();

        Ok(tx_array)
    }
}
