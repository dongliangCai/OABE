//! The fraud Circuit is a circuit for DU to generate zk fraud proof
use std::{iter, marker::PhantomData};

use crate::util::Field;
use bus_mapping::{
    circuit_input_builder::{EcAddOp, EcMulOp, EcPairingOp, N_BYTES_PER_PAIR, N_PAIRING_PER_OP},
    precompile::PrecompileCalls,
};
use eth_types::{ToLittleEndian, U256, H256};
use ethers_core::{utils::keccak256, k256::elliptic_curve::Group};
use gadgets::ToScalar;
use halo2_base::{
    gates::{GateInstructions, RangeInstructions},
    utils::{decompose_bigint_option, fe_to_biguint, modulus},
    AssignedValue, Context, QuantumCell, SKIP_FIRST_PASS,
};
use halo2_ecc::{
    bigint::{big_is_zero, CRTInteger, OverflowInteger},
    bn254::pairing::PairingChip,
    ecc::{EcPoint, EccChip},
    fields::{
        fp::{FpConfig, FpStrategy},
        fp12::Fp12Chip,
        fp2::Fp2Chip,
        FieldChip, FieldExtPoint, FieldExtConstructor,
    },
};
use halo2_proofs::{
    circuit::{Layouter, Value},
    halo2curves::{
        bn256::{Fq, Fq12, Fq2, Fr, G1Affine, G2Affine, Gt, G1, G2},
        CurveAffine,
    },
    plonk::{ConstraintSystem, Error, Expression, Column, Advice, Instance},
};
use itertools::Itertools;
use log::error;
use num::BigInt;
use rand_chacha::rand_core::OsRng;
use snark_verifier::util::arithmetic::PrimeCurveAffine;
use snark_verifier_sdk::CircuitExt;

use crate::{
    evm_circuit::{param::N_BYTES_WORD, EvmCircuit},
    keccak_circuit::KeccakCircuit,
    table::{EccTable, LookupTable},
    util::{Challenges, SubCircuit, SubCircuitConfig},
    witness::Block,
};
use ark_std::start_timer;

mod util;
mod dev;
mod test;

use util::{
    EcAddAssigned, EcAddDecomposed, EcMulAssigned, EcMulDecomposed, EcOpsAssigned,
    EcPairingAssigned, EcPairingDecomposed, G1Assigned, G1Decomposed, G2Decomposed, ScalarAssigned,
    LOG_TOTAL_NUM_ROWS,
};

/// Arguments accepted to configure the MyEccCircuitConfig.
#[derive(Clone, Debug)]
pub struct MyFraudCircuitConfigArgs<F: Field> {
    /// zkEVM challenge API.
    pub challenges: Challenges<Expression<F>>,
}

/// Config for the my ECC circuit.
#[derive(Clone, Debug)]
pub struct MyFraudCircuitConfig<F: Field> {
    /// Field config for halo2_proofs::halo2curves::bn256::Fq.
    fp_config: FpConfig<F, Fq>,
    /// Number of limbs to represent Fp.
    num_limbs: usize,
    /// Number of bits per limb.
    limb_bits: usize,

    hash: Column<Advice>,
    instance: Column<Instance>,

    _marker: PhantomData<F>,
}

impl<F: Field> SubCircuitConfig<F> for MyFraudCircuitConfig<F> {
    type ConfigArgs = MyFraudCircuitConfigArgs<F>;

    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs {
            challenges: _,
        }: Self::ConfigArgs,
    ) -> Self {
        let num_limbs = 3;
        let limb_bits = 88;
        // #[cfg(feature = "onephase")]
        let num_advice = [35];
        // #[cfg(not(feature = "onephase"))]
        // let num_advice = [35, 1];

        let fp_config = FpConfig::configure(
            meta,
            FpStrategy::Simple,
            &num_advice,
            &[17], // num lookup advice
            1,     // num fixed
            13,    // lookup bits
            limb_bits,
            num_limbs,
            modulus::<Fq>(),
            0,
            14 as usize, // k
        );

        let hash = meta.advice_column();
        let instance = meta.instance_column();

        meta.enable_equality(hash);
        meta.enable_equality(instance);

        Self {
            fp_config,
            num_limbs,
            limb_bits,
            hash,
            instance,
            _marker: PhantomData,
        }
    }
}

/// My Fraud Circuit responsible for verifying the following
/// first check g^sk = pk
/// second check c1 * c2^sk = tag
#[derive(Clone, Debug, Default)]
pub struct MyFraudCircuit<F: Field, const XI_0: i64> {
    /// g
    pub g: (U256, U256),
    /// pk
    pub pk: (U256, U256),
    /// sk
    pub sk: Fr,

    /// transform ct
    pub c1: Fq12,
    /// transform ct
    pub c2: Fq12,

    ///tag
    pub tag: Fq12,

    ///PhantomData
    pub _marker: PhantomData<F>,
}

impl<F: Field, const XI_0: i64> MyFraudCircuit<F, XI_0>{
    /// Return the minimum number of rows required to prove an input of a
    /// particular size.
    pub fn min_num_rows() -> usize {
        // EccCircuit can't determine usable rows independently.
        // Instead, the blinding area is determined by other advise columns with most counts of
        // rotation queries. This value is typically determined by either the Keccak or EVM
        // circuit.

        let max_blinding_factor = Self::unusable_rows() - 1;

        // same formula as halo2-lib's FlexGate
        (1 << 20) - (max_blinding_factor + 3)
    }

    /// Assign witness from the ecXX ops to the circuit.
    pub(crate) fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        config: &<Self as SubCircuit<F>>::Config,
        challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        
        let powers_of_256 = iter::successors(Some(F::one()), |coeff| Some(F::from(256) * coeff))
            .take(N_BYTES_WORD)
            .map(|x| QuantumCell::Constant(x))
            .collect_vec();
        let ecc_chip = EccChip::<F, FpConfig<F, Fq>>::construct(config.fp_config.clone());
        let fr_chip = FpConfig::<F, Fr>::construct(
            config.fp_config.range.clone(),
            config.limb_bits,
            config.num_limbs,
            modulus::<Fr>(),
        );
        let pairing_chip = PairingChip::construct(config.fp_config.clone());
        let fp12_chip =
            Fp12Chip::<F, FpConfig<F, Fq>, Fq12, XI_0>::construct(config.fp_config.clone());

        let fp2_chip = Fp2Chip::<F, FpConfig<F, Fq>, Fq2>::construct(pairing_chip.fp_chip.clone());

        let assign_ecc = layouter.assign_region(
            || "fraud circuit",
            |mut region| {
                let mut ctx = config.fp_config.new_context(region);

                let (g1x, g1x_cells, g1x_valid, g1x_is_zero) =
                    self.precheck_fq(&mut ctx, &ecc_chip,self.g.0 , powers_of_256.as_slice());
                let (g1y, g1y_cells, g1y_valid, g1y_is_zero) =
                    self.precheck_fq(&mut ctx, &ecc_chip, self.g.1, powers_of_256.as_slice());
                let g_point = EcPoint::<F, CRTInteger<F>>::construct(g1x, g1y);

                let (pkx, pkx_cells, pkx_valid, pkx_is_zero) =
                    self.precheck_fq(&mut ctx, &ecc_chip,self.pk.0 , powers_of_256.as_slice());
                let (pky, pky_cells, pky_valid, pky_is_zero) =
                    self.precheck_fq(&mut ctx, &ecc_chip, self.pk.1, powers_of_256.as_slice());
                let pk_point = EcPoint::<F, CRTInteger<F>>::construct(pkx, pky);

                let sk = self.handle_fr(&mut ctx, &fr_chip, self.sk).scalar.limbs().to_vec();

                let g_mul_sk = ecc_chip.scalar_mult(
                    &mut ctx,
                    &g_point,
                    &sk,
                    fr_chip.limb_bits,
                    4,
                );

                ecc_chip.assert_equal(&mut ctx, &g_mul_sk, &pk_point);

                let c1_coeff= self.c1.coeffs().iter().map(|c| Value::known(BigInt::from(fe_to_biguint(c)))).collect();
                let c1_point = fp12_chip.load_private(&mut ctx, c1_coeff);

                let c2_coeff= self.c2.coeffs().iter().map(|c| Value::known(BigInt::from(fe_to_biguint(c)))).collect();
                let c2_point = fp12_chip.load_private(&mut ctx, c2_coeff);

                let res = fp12_chip.mul(&mut ctx, &c1_point, &c2_point);

                let tag = fp12_chip.load_constant(&mut ctx, self.tag);
                
                let success = fp12_chip.assert_equal(&mut ctx, &res, &tag);

                ctx.print_stats(&["EccCircuit: FpConfig Full Context"]);
                Ok(success)
                // Ok(())
            });

        Ok(())
    }
    /// Precheck a 32-bytes word input supposed to be bn256::Fq and return its CRT integer
    /// representation. We also return the LE-bytes and assigned values to indicate whether the
    /// value is within Fq::MODULUS and whether or not it is zero.
    fn precheck_fq(
        &self,
        ctx: &mut Context<F>,
        ecc_chip: &EccChip<F, FpConfig<F, Fq>>,
        word_value: U256,
        powers_of_256: &[QuantumCell<F>],
    ) -> (
        CRTInteger<F>,       // CRT representation.
        Vec<QuantumCell<F>>, // LE bytes as witness.
        AssignedValue<F>,    // value < Fq::MODULUS
        AssignedValue<F>,    // value == 0
    ) {
        let value = Value::known(num_bigint::BigInt::from(
            num_bigint::BigUint::from_bytes_le(&word_value.to_le_bytes()),
        ));
        let vec_value = decompose_bigint_option::<F>(
            value.as_ref(),
            ecc_chip.field_chip.num_limbs,
            ecc_chip.field_chip.limb_bits,
        );
        let limbs = ecc_chip
            .field_chip()
            .range()
            .gate()
            .assign_witnesses(ctx, vec_value);
        let native_value = OverflowInteger::evaluate(
            ecc_chip.field_chip().range().gate(),
            ctx,
            &limbs,
            ecc_chip.field_chip.limb_bases.iter().cloned(),
        );
        let overflow_int = OverflowInteger::construct(limbs, ecc_chip.field_chip.limb_bits);
        let crt_int = CRTInteger::construct(overflow_int, native_value, value);
        let cells = word_value
            .to_le_bytes()
            .map(|b| QuantumCell::Witness(Value::known(F::from(b as u64))));
        self.assert_crt_repr(ctx, ecc_chip, &crt_int, &cells, powers_of_256);
        let is_lt_mod = ecc_chip.field_chip().is_less_than_p(ctx, &crt_int);
        let is_zero = big_is_zero::positive(
            ecc_chip.field_chip().range().gate(),
            ctx,
            &crt_int.truncation,
        );
        let is_zero = ecc_chip.field_chip().range().gate().and(
            ctx,
            QuantumCell::Existing(is_lt_mod),
            QuantumCell::Existing(is_zero),
        );
        (crt_int, cells.to_vec(), is_lt_mod, is_zero)
    }
    /// Assert that a CRT integer's bytes representation matches the limb values.
    fn assert_crt_repr(
        &self,
        ctx: &mut Context<F>,
        ecc_chip: &EccChip<F, FpConfig<F, Fq>>,
        crt_int: &CRTInteger<F>,
        bytes: &[QuantumCell<F>],
        powers_of_256: &[QuantumCell<F>],
    ) {
        debug_assert_eq!(bytes.len(), 32);
        debug_assert!(powers_of_256.len() >= 11);

        let limbs = [
            bytes[0..11].to_vec(),
            bytes[11..22].to_vec(),
            bytes[22..32].to_vec(),
        ]
        .map(|limb_bytes| {
            ecc_chip.field_chip().range().gate().inner_product(
                ctx,
                limb_bytes,
                powers_of_256[0..11].to_vec(),
            )
        });

        for (&limb_recovered, &limb_value) in limbs.iter().zip_eq(crt_int.truncation.limbs.iter()) {
            ecc_chip.field_chip().range().gate().assert_equal(
                ctx,
                QuantumCell::Existing(limb_recovered),
                QuantumCell::Existing(limb_value),
            );
        }
    }

    /// Handle a scalar field element and return its assigned state.
    fn handle_fr(
        &self,
        ctx: &mut Context<F>,
        fr_chip: &FpConfig<F, Fr>,
        s: Fr,
    ) -> ScalarAssigned<F> {
        let scalar = fr_chip.load_private(ctx, FpConfig::<F, Fr>::fe_to_witness(&Value::known(s)));
        ScalarAssigned { scalar }
    }
}

impl<F: Field, const XI_0: i64> SubCircuit<F> for MyFraudCircuit<F, XI_0> {
    type Config = MyFraudCircuitConfig<F>;
    

    fn new_from_block(block: &Block) -> Self {
        unimplemented!()
        // let alpha = F::random(OsRng);
        // let beta = F::random(OsRng);
        // let alpha = U256::from_little_endian(&alpha.to_bytes_le());


        // Self {
        //     p1s: vec![(alpha, alpha)],
        //     p2s: vec![(alpha, alpha, alpha, alpha)],

        //     ti: Fq12::one(),
        //     _marker: PhantomData,
        // }
    }

    /// Returns number of unusable rows of the SubCircuit, which should be
    /// `meta.blinding_factors() + 1`.
    fn unusable_rows() -> usize {
        [
            KeccakCircuit::<F>::unusable_rows(),
            EvmCircuit::<F>::unusable_rows(),
            // may include additional subcircuits here
        ]
        .into_iter()
        .max()
        .unwrap()
    }

    // ///c_i d_i
    // p1s: Vec<(U256, U256)>,
    // ///R_i
    // p2s: Vec<(U256, U256, U256, U256)>,
    // // w_i 
    // ws: Vec<Fr>,
    // // L
    // p4: (U256, U256, U256, U256),
    // ///test
    // ti: Fq12,
    // 2n Fq2  (n+1) (Fq4)  n Fr   1 Fq12  =   (8n+16) Fq + n Fr    32 bytes

    /// Compute the public inputs for this circuit.
    fn instance(&self) -> Vec<Vec<F>> {
        vec![vec![]]
    }

    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        config.fp_config.range.load_lookup_table(layouter)?;
        self.assign(layouter, config, challenges)?;
        Ok(())
    }

    fn min_num_rows_block(block: &Block) -> (usize, usize) {
        let row_num = if block.circuits_params.max_vertical_circuit_rows == 0 {
            Self::min_num_rows()
        } else {
            block.circuits_params.max_vertical_circuit_rows
        };

        let ec_adds = block.get_ec_add_ops().len();
        let ec_muls = block.get_ec_mul_ops().len();
        let ec_pairings = block.get_ec_pairing_ops().len();
        let max_ec_ops = &block.circuits_params.max_ec_ops;
        log::debug!("ecc circuit row usage: ecadd {ec_adds}/{}, ecmul {ec_muls}/{}, ecpairing {ec_pairings}/{}",
        max_ec_ops.ec_add, max_ec_ops.ec_mul, max_ec_ops.ec_pairing);

        // Instead of showing actual minimum row usage,
        // halo2-lib based circuits use min_row_num to represent a percentage of total-used capacity
        // This functionality allows l2geth to decide if additional ops can be added.
        let min_row_num = [
            (row_num / max_ec_ops.ec_add) * ec_adds,
            (row_num / max_ec_ops.ec_mul) * ec_muls,
            (row_num / max_ec_ops.ec_pairing) * ec_pairings,
        ]
        .into_iter()
        .max()
        .unwrap();

        (min_row_num, row_num)
    }
}

impl<const XI_0: i64> CircuitExt<Fr> for  MyFraudCircuit<Fr, XI_0>  {
    /// 32 elements from digest
    fn num_instance(&self) -> Vec<usize> {
        self.instances().iter().map(|l| l.len()).collect_vec()
    }

    /// return vec![acc | public input hash]
    fn instances(&self) -> Vec<Vec<Fr>> {
        self.instance()
    }
}