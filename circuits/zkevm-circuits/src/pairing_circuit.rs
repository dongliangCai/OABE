//! The pairing Circuit is a circuit that prove Gt = pairing(a,b)*pairing(c,d)
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
pub struct MyEccCircuitConfigArgs<F: Field> {
    /// zkEVM challenge API.
    pub challenges: Challenges<Expression<F>>,
}

/// Config for the my ECC circuit.
#[derive(Clone, Debug)]
pub struct MyEccCircuitConfig<F: Field> {
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

impl<F: Field> SubCircuitConfig<F> for MyEccCircuitConfig<F> {
    type ConfigArgs = MyEccCircuitConfigArgs<F>;

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
            19 as usize, // k
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

/// My ECC Circuit responsible for verifying the following
// ti = e(ci^wi, L) * e(di^wi, ri)
// n = 10   T = t1 * t2 * .. * t10
#[derive(Clone, Debug, Default)]
pub struct MyEccCircuit<F: Field, const XI_0: i64> {
    ///c_i d_i
    pub p1s: Vec<(U256, U256)>,
    ///R_i
    pub p2s: Vec<(U256, U256, U256, U256)>,
    /// w_i 
    pub ws: Vec<Fr>,
    /// L
    pub p4: (U256, U256, U256, U256),
    /// C'
    pub ct: (U256, U256),
    /// R'
    pub tk: (U256, U256, U256, U256),
    /// test
    pub ti: Fq12,
    /// test
    pub _marker: PhantomData<F>,
}

impl<F: Field, const XI_0: i64> MyEccCircuit<F, XI_0>{
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

        // keccak powers of randomness.
        let keccak_powers = std::iter::successors(Some(Value::known(F::one())), |coeff| {
            Some(challenges.keccak_input() * coeff)
        })
        .take(N_PAIRING_PER_OP * N_BYTES_PER_PAIR)
        .map(|x| QuantumCell::Witness(x))
        .collect_vec();

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

        println!("begin assign");

        let assign_ecc = layouter.assign_region(
            || "ecc circuit",
            |mut region| {

                let mut ctx = config.fp_config.new_context(region);

                let mut pairs = vec![];
                let mut c_g1_points = vec![];
                let mut d_g1_points = vec![];
                let mut g2_points = vec![];
                let mut ws = vec![];
                
                let mut d_g1_points_mul_w = vec![];
                
                //process C_i  D_i
                for i in 0..(self.p1s.len()/2){
                    let ci = 2 * i;
                    let (g1x, g1x_cells, g1x_valid, g1x_is_zero) =
                        self.precheck_fq(&mut ctx, &ecc_chip,self.p1s[ci].0 , powers_of_256.as_slice());
                    let (g1y, g1y_cells, g1y_valid, g1y_is_zero) =
                        self.precheck_fq(&mut ctx, &ecc_chip, self.p1s[ci].1, powers_of_256.as_slice());
                    let c_g1_point = EcPoint::<F, CRTInteger<F>>::construct(g1x, g1y);
                    c_g1_points.push(c_g1_point);

                    let di = ci + 1;
                    let (g1x, g1x_cells, g1x_valid, g1x_is_zero) =
                        self.precheck_fq(&mut ctx, &ecc_chip,self.p1s[di].0 , powers_of_256.as_slice());
                    let (g1y, g1y_cells, g1y_valid, g1y_is_zero) =
                        self.precheck_fq(&mut ctx, &ecc_chip, self.p1s[di].1, powers_of_256.as_slice());
                    let d_g1_point = EcPoint::<F, CRTInteger<F>>::construct(g1x, g1y);
                    d_g1_points.push(d_g1_point);
                }

                //process w_i
                for w_i in self.ws.iter() {
                    ws.push(self.handle_fr(&mut ctx, &fr_chip, *w_i).scalar.limbs().to_vec());
                }

                // let zero = G1Affine::from(G1::identity());
                // let (g1x, g1x_cells, g1x_valid, g1x_is_zero) =
                //     self.precheck_fq(&mut ctx, &ecc_chip,U256::from_little_endian(&zero.x.to_bytes()), powers_of_256.as_slice());
                // let (g1y, g1y_cells, g1y_valid, g1y_is_zero) =
                //     self.precheck_fq(&mut ctx, &ecc_chip, U256::from_little_endian(&zero.y.to_bytes()), powers_of_256.as_slice());

                let mut c_g1_points_mul_w = ecc_chip.scalar_mult(
                    &mut ctx,
                    &c_g1_points[0],
                    &ws[0],
                    fr_chip.limb_bits,
                    4,
                );
                
                // c_g1_points_mul_w = ecc_chip.add_unequal(&mut ctx, &c_g1_points_mul_w, &zero, false);

                for i in 1..c_g1_points.len() {
                    let c_g1_points_mul_w_i = ecc_chip.scalar_mult(
                        &mut ctx,
                        &c_g1_points[i],
                        &ws[i],
                        fr_chip.limb_bits,
                        4,
                    );
                    c_g1_points_mul_w = ecc_chip.add_unequal(&mut ctx, &c_g1_points_mul_w, &c_g1_points_mul_w_i, false);
                }
                for i in 0..d_g1_points.len() {
                    d_g1_points_mul_w.push(ecc_chip.scalar_mult(
                        &mut ctx,
                        &d_g1_points[i],
                        &ws[i],
                        fr_chip.limb_bits,
                        4,
                    ))
                }
                //process L
                let (g2x0, g2x0_cells, g2x0_valid, g2x0_is_zero) =
                self.precheck_fq(&mut ctx, &ecc_chip, self.p4.1, powers_of_256.as_slice());
                let (g2x1, g2x1_cells, g2x1_valid, g2x1_is_zero) =
                    self.precheck_fq(&mut ctx, &ecc_chip, self.p4.0, powers_of_256.as_slice());
                let (g2y0, g2y0_cells, g2y0_valid, g2y0_is_zero) =
                    self.precheck_fq(&mut ctx, &ecc_chip, self.p4.3, powers_of_256.as_slice());
                let (g2y1, g2y1_cells, g2y1_valid, g2y1_is_zero) =
                    self.precheck_fq(&mut ctx, &ecc_chip, self.p4.2, powers_of_256.as_slice());
                let L_point = EcPoint::<F, FieldExtPoint<CRTInteger<F>>>::construct(
                    FieldExtPoint::construct(vec![g2x0, g2x1]),
                    FieldExtPoint::construct(vec![g2y0, g2y1]),
                );

                //process R_i
                for p2 in self.p2s.iter() {
                    // process x and y co-ordinates of G2.
                    let (g2x0, g2x0_cells, g2x0_valid, g2x0_is_zero) =
                        self.precheck_fq(&mut ctx, &ecc_chip, p2.1, powers_of_256.as_slice());
                    let (g2x1, g2x1_cells, g2x1_valid, g2x1_is_zero) =
                        self.precheck_fq(&mut ctx, &ecc_chip, p2.0, powers_of_256.as_slice());
                    let (g2y0, g2y0_cells, g2y0_valid, g2y0_is_zero) =
                        self.precheck_fq(&mut ctx, &ecc_chip, p2.3, powers_of_256.as_slice());
                    let (g2y1, g2y1_cells, g2y1_valid, g2y1_is_zero) =
                        self.precheck_fq(&mut ctx, &ecc_chip, p2.2, powers_of_256.as_slice());
                    let g2_point = EcPoint::<F, FieldExtPoint<CRTInteger<F>>>::construct(
                        FieldExtPoint::construct(vec![g2x0, g2x1]),
                        FieldExtPoint::construct(vec![g2y0, g2y1]),
                    );
                    g2_points.push(g2_point);
                }
                
                //(Ci, L) (D_i, R_i)

                pairs.push((&c_g1_points_mul_w, &L_point));

                for i in 0..d_g1_points_mul_w.len() {
                    pairs.push((&d_g1_points_mul_w[i], &g2_points[i]));
        
                }


                //process C' R'
                let (g1x, g1x_cells, g1x_valid, g1x_is_zero) =
                    self.precheck_fq(&mut ctx, &ecc_chip, self.ct.0, powers_of_256.as_slice());
                let (g1y, g1y_cells, g1y_valid, g1y_is_zero) =
                    self.precheck_fq(&mut ctx, &ecc_chip, self.ct.1, powers_of_256.as_slice());
                let C_p_point = EcPoint::<F, CRTInteger<F>>::construct(g1x, g1y);


                let (g2x0, g2x0_cells, g2x0_valid, g2x0_is_zero) =
                self.precheck_fq(&mut ctx, &ecc_chip, self.tk.1, powers_of_256.as_slice());
                let (g2x1, g2x1_cells, g2x1_valid, g2x1_is_zero) =
                    self.precheck_fq(&mut ctx, &ecc_chip, self.tk.0, powers_of_256.as_slice());
                let (g2y0, g2y0_cells, g2y0_valid, g2y0_is_zero) =
                    self.precheck_fq(&mut ctx, &ecc_chip, self.tk.3, powers_of_256.as_slice());
                let (g2y1, g2y1_cells, g2y1_valid, g2y1_is_zero) =
                    self.precheck_fq(&mut ctx, &ecc_chip, self.tk.2, powers_of_256.as_slice());
                let Rp_point = EcPoint::<F, FieldExtPoint<CRTInteger<F>>>::construct(
                    FieldExtPoint::construct(vec![g2x0, g2x1]),
                    FieldExtPoint::construct(vec![g2y0, g2y1]),
                );

                pairs.push((&C_p_point, &Rp_point));
                // let pairs = vec![(&g1_point, &g2_point)];
                let success = {
                    let gt = {
                        let gt = pairing_chip.multi_miller_loop(&mut ctx, pairs);
                        pairing_chip.final_exp(&mut ctx, &gt)
                    };

                    // let gt_chip = EccChip::construct(fp12_chip);
                    // gt_chip.scalar_mult(
                    //     &mut ctx,
                    //     &gt_point,
                    //     &ws[0],
                    //     fr_chip.limb_bits,
                    //     4,);


                    ctx.print_stats(&["EccCircuit: after gt_denomenator Context"]);
                    // let gt_numerator = {
                    //     let gt = pairing_chip.multi_miller_loop(&mut ctx, vec![(&C_p_point, &Rp_point)]);
                    //     pairing_chip.final_exp(&mut ctx, &gt)
                    // };
                    // ctx.print_stats(&["EccCircuit: after gt_numerator Context"]);
                    // for i in 0..gt.coeffs.len() {
                    //     println!("recover gt i:{} :{:?}", i, gt.coeffs[i].truncation.limbs[0]);
                    //     println!("recover gt i:{} :{:?}", i, gt.coeffs[i].truncation.limbs[1]);
                    //     println!("recover gt i:{} :{:?}", i, gt.coeffs[i].truncation.limbs[2]);
                    // }
                    
                    let ti = fp12_chip.load_constant(&mut ctx, self.ti);

                    

                    // let left = fp12_chip.mul(&mut ctx, &ti, &gt_denomenator);
                    // for i in 0..ti.coeffs.len() {
                    //     println!("real gt i:{} :{:?}", i, ti.coeffs[i].truncation.limbs[0]);
                    //     println!("real gt i:{} :{:?}", i, ti.coeffs[i].truncation.limbs[1]);
                    //     println!("real gt i:{} :{:?}", i, ti.coeffs[i].truncation.limbs[2]);
                    // }
                    fp12_chip.assert_equal(&mut ctx, &gt, &ti)
                };                
                ctx.print_stats(&["EccCircuit: FpConfig Full Context"]);
                
                Ok(success)
            });

            println!("begin assign hash");

            let cells = layouter.assign_region(
                || "expose pi hash",
                |mut region| {

                    let mut cells = vec![];
                    let instance = self.instance()[0].clone();
                    let mut offset = 0;

                    for i in 0..instance.len() {

                        let cell = region.assign_advice(
                            ||"assign pi hash", 
                            config.hash, 
                            offset, 
                            || Value::known(instance[i])
                        )?;
                        cells.push(cell);
                        offset += 1;
                    }
                    Ok(cells)          
                },
            )?;
            println!("end assign hash");
            // for i in 0..cells.len() {
            //     println!("index{:?}", i);
            //     layouter.constrain_instance(cells[i].cell(), config.instance, i)?;
            // }

            Ok(())
    }

    /// Return an assigned value that indicates whether the given point is on curve G1 or identity
    /// point.
    fn is_on_curveg1_or_infinity(
        &self,
        ctx: &mut Context<F>,
        ecc_chip: &EccChip<F, FpConfig<F, Fq>>,
        x: &CRTInteger<F>,
        x_is_zero: AssignedValue<F>,
        y: &CRTInteger<F>,
        y_is_zero: AssignedValue<F>,
    ) -> AssignedValue<F> {
        let lhs = ecc_chip.field_chip().mul_no_carry(ctx, y, y);
        let mut rhs = ecc_chip.field_chip().mul(ctx, x, x);
        rhs = ecc_chip.field_chip().mul_no_carry(ctx, &rhs, x);

        let b = FpConfig::<F, Fq>::fe_to_constant(G1Affine::b());
        rhs = ecc_chip.field_chip().add_constant_no_carry(ctx, &rhs, b);
        let mut diff = ecc_chip.field_chip().sub_no_carry(ctx, &lhs, &rhs);
        diff = ecc_chip.field_chip().carry_mod(ctx, &diff);

        let is_on_curve = ecc_chip.field_chip().is_zero(ctx, &diff);

        ecc_chip.field_chip().range().gate().or_and(
            ctx,
            QuantumCell::Existing(is_on_curve),
            QuantumCell::Existing(x_is_zero),
            QuantumCell::Existing(y_is_zero),
        )
    }

    /// Return an assigned value that indicates whether the given point is on curve G2 or identity
    /// point.
    fn is_on_curveg2_or_infinity(
        &self,
        ctx: &mut Context<F>,
        fp2_chip: &Fp2Chip<F, FpConfig<F, Fq>, Fq2>,
        x: &FieldExtPoint<CRTInteger<F>>,
        x_is_zero: AssignedValue<F>,
        y: &FieldExtPoint<CRTInteger<F>>,
        y_is_zero: AssignedValue<F>,
    ) -> AssignedValue<F> {
        let lhs = fp2_chip.mul_no_carry(ctx, y, y);
        let mut rhs = fp2_chip.mul(ctx, x, x);
        rhs = fp2_chip.mul_no_carry(ctx, &rhs, x);

        let b = Fp2Chip::<F, FpConfig<F, Fq>, Fq2>::fe_to_constant(G2Affine::b());
        rhs = fp2_chip.add_constant_no_carry(ctx, &rhs, b);
        let mut diff = fp2_chip.sub_no_carry(ctx, &lhs, &rhs);
        diff = fp2_chip.carry_mod(ctx, &diff);

        let is_on_curve = fp2_chip.is_zero(ctx, &diff);

        fp2_chip.range().gate().or_and(
            ctx,
            QuantumCell::Existing(is_on_curve),
            QuantumCell::Existing(x_is_zero),
            QuantumCell::Existing(y_is_zero),
        )
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

    /// Decompose G1 element into cells representing its x and y co-ordinates.
    fn decompose_g1(&self, g1: G1Affine) -> (Vec<QuantumCell<F>>, Vec<QuantumCell<F>>) {
        (
            g1.x.to_bytes()
                .iter()
                .map(|&x| QuantumCell::Witness(Value::known(F::from(u64::from(x)))))
                .collect_vec(),
            g1.y.to_bytes()
                .iter()
                .map(|&y| QuantumCell::Witness(Value::known(F::from(u64::from(y)))))
                .collect_vec(),
        )
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
    /// Handle G1 point and return its decomposed state.
        fn handle_g1(
            &self,
            ctx: &mut Context<F>,
            ecc_chip: &EccChip<F, FpConfig<F, Fq>>,
            g1: G1Affine,
            powers_of_256: &[QuantumCell<F>],
        ) -> G1Decomposed<F> {
            let ec_point = ecc_chip.load_private(ctx, (Value::known(g1.x), Value::known(g1.y)));
            let (x_cells, y_cells) = self.decompose_g1(g1);
            self.assert_crt_repr(ctx, ecc_chip, &ec_point.x, &x_cells, powers_of_256);
            self.assert_crt_repr(ctx, ecc_chip, &ec_point.y, &y_cells, powers_of_256);
            G1Decomposed {
                ec_point,
                x_cells,
                y_cells,
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

impl<F: Field, const XI_0: i64> SubCircuit<F> for MyEccCircuit<F, XI_0> {
    type Config = MyEccCircuitConfig<F>;
    

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
        let mut bytes = Vec::with_capacity(4000);
        
        for i in 0..self.p1s.len() {
            bytes.extend_from_slice(&self.p1s[i].0.to_le_bytes().as_slice());
            bytes.extend_from_slice(&self.p1s[i].1.to_le_bytes().as_slice());
        }
       
        for i in 0..self.p2s.len() {
            bytes.extend_from_slice(&self.p2s[i].0.to_le_bytes().as_slice());
            bytes.extend_from_slice(&self.p2s[i].1.to_le_bytes().as_slice());
            bytes.extend_from_slice(&self.p2s[i].2.to_le_bytes().as_slice());
            bytes.extend_from_slice(&self.p2s[i].3.to_le_bytes().as_slice());
        }

        for i in 0..self.ws.len() {
            bytes.extend_from_slice(&self.ws[i].to_bytes().as_slice());
        }

        bytes.extend_from_slice(&self.p4.0.to_le_bytes().as_slice());
        bytes.extend_from_slice(&self.p4.1.to_le_bytes().as_slice());
        bytes.extend_from_slice(&self.p4.2.to_le_bytes().as_slice());
        bytes.extend_from_slice(&self.p4.3.to_le_bytes().as_slice());

        bytes.extend_from_slice(&self.ct.0.to_le_bytes().as_slice());
        bytes.extend_from_slice(&self.ct.1.to_le_bytes().as_slice());

        bytes.extend_from_slice(&self.tk.0.to_le_bytes().as_slice());
        bytes.extend_from_slice(&self.tk.1.to_le_bytes().as_slice());
        bytes.extend_from_slice(&self.tk.2.to_le_bytes().as_slice());
        bytes.extend_from_slice(&self.tk.3.to_le_bytes().as_slice());

        let mut result_bytes = Vec::new();
        for i in self.ti.coeffs().iter() {
            result_bytes.extend_from_slice(i.to_bytes().as_slice());
        }

        let data_hash = keccak256(bytes);
        
        let mut pi_bytes = Vec::new();
        pi_bytes.extend_from_slice(data_hash.as_slice());
        pi_bytes.extend_from_slice(result_bytes.as_slice());

        let pi_hash = H256(keccak256(pi_bytes));
        let public_inputs = iter::empty()
        .chain(
            pi_hash
                .to_fixed_bytes()
                .into_iter()
                .map(|byte| F::from(byte as u64)),
        )
        .collect::<Vec<F>>();
        vec![public_inputs]
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

impl<const XI_0: i64> CircuitExt<Fr> for  MyEccCircuit<Fr, XI_0>  {
    /// 32 elements from digest
    fn num_instance(&self) -> Vec<usize> {
        self.instances().iter().map(|l| l.len()).collect_vec()
    }

    /// return vec![acc | public input hash]
    fn instances(&self) -> Vec<Vec<Fr>> {
        self.instance()
    }
}

