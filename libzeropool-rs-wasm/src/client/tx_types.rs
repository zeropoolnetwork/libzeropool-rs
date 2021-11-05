use crate::{Fr, IDepositData, ITransferData, IWithdrawData};
use libzeropool_rs::client::{TokenAmount, TxOutput, TxType as NativeTxType};
use serde::Deserialize;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub enum TxType {
    Transfer = "transfer",
    Deposit = "deposit",
    Withdraw = "withdraw",
}

pub trait JsTxType {
    fn to_native(&self) -> Result<NativeTxType<Fr>, JsValue>;
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
    base_fields: TxBaseFields,
    amount: TokenAmount<Fr>,
}

impl JsTxType for IDepositData {
    fn to_native(&self) -> Result<NativeTxType<Fr>, JsValue> {
        let DepositData {
            base_fields,
            amount,
        } = serde_wasm_bindgen::from_value(self.into())?;

        Ok(NativeTxType::Deposit(
            base_fields.fee,
            base_fields.data.unwrap_or(vec![]),
            amount,
        ))
    }
}

#[derive(Deserialize)]
struct Output {
    to: String,
    amount: TokenAmount<Fr>,
}

#[wasm_bindgen]
#[derive(Deserialize)]
pub struct TransferData {
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
            base_fields.data.unwrap_or(vec![]),
            outputs,
        ))
    }
}

#[wasm_bindgen]
#[derive(Deserialize)]
pub struct WithdrawData {
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
            base_fields.data.unwrap_or(vec![]),
            amount,
            to,
            native_amount,
            energy_amount,
        ))
    }
}
