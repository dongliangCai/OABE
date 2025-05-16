use std::{marker::PhantomData, ops::Mul};

use bus_mapping::circuit_input_builder::EcPairingPair;
use eth_types::U256;
use ethers_core::k256::elliptic_curve::Group;
use ff::Field;
use rand::Rng;
use halo2_proofs::{
    circuit::{Layouter, Value},
    halo2curves::{
        bn256::{Fq, Fq12, Fq2, Fr, G1Affine, G2Affine, Gt, G1, G2, pairing, Bn256},
        CurveAffine,
    },
    plonk::{ConstraintSystem, Error, Expression, keygen_vk, keygen_pk}, dev::MockProver, poly::kzg::commitment::ParamsKZG,
};
use rand_chacha::rand_core::OsRng;

use halo2_proofs::plonk::create_proof;
use halo2_proofs::plonk::verify_proof;
use halo2_proofs::poly::kzg::commitment::KZGCommitmentScheme;
use halo2_proofs::poly::kzg::multiopen::ProverGWC;
use halo2_proofs::poly::kzg::multiopen::VerifierGWC;
use halo2_proofs::poly::kzg::strategy::SingleStrategy;
use halo2_proofs::transcript::Blake2bRead;
use halo2_proofs::transcript::Blake2bWrite;
use halo2_proofs::transcript::Challenge255;
use halo2_proofs::transcript::TranscriptReadBuffer;
use halo2_proofs::transcript::TranscriptWriterBuffer;

use ark_std::{start_timer, end_timer};
use snark_verifier_sdk::{gen_snark_shplonk, Snark};

use crate::util::SubCircuit;

use super::MyFraudCircuit;

#[test]
fn test_fraud_circuit() {
    let mut g1 = G1Affine::random(&mut OsRng);
    let sk = Fr::random(&mut OsRng);
    let mut pk1 = G1Affine::from(g1.mul(sk));

    let g = (U256::from_little_endian(&g1.x.to_bytes()), U256::from_little_endian(&g1.y.to_bytes()));
    let pk = (U256::from_little_endian(&pk1.x.to_bytes()), U256::from_little_endian(&pk1.y.to_bytes()));

    let c1 = Fq12::random(&mut OsRng);

    let c2 = Fq12::random(&mut OsRng);
    
    let tag = c1 * c2;


    let circuit = MyFraudCircuit::<Fr, 9>{
        g,
        sk,
        pk,
        c1,
        c2,
        tag,
        _marker: PhantomData,
    };

    let k = 18;

    let instance = circuit.instance();

    let instance_refs: Vec<&[Fr]> = instance.iter().map(|v| &v[..]).collect();

    let timer = start_timer!(|| format!("build params with K = {}", k));

    let params = ParamsKZG::<Bn256>::setup(k, OsRng);
    // let params: Params<G1Affine> = Params::<G1Affine>::unsafe_setup::<grumpkin>(k);
    end_timer!(timer);

    let timer = start_timer!(|| "build vk");
    let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
    end_timer!(timer);

    let timer = start_timer!(|| "build pk");
    let pk = keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail");
    end_timer!(timer);

    let timer = start_timer!(|| "create proof");
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);

    create_proof::<
        KZGCommitmentScheme<Bn256>,
        ProverGWC<'_, Bn256>,
        Challenge255<G1Affine>,
        _,
        Blake2bWrite<Vec<u8>, G1Affine, Challenge255<_>>,
        _,
    >(
        &params,
        &pk,
        &[circuit],
        &[&instance_refs],
        OsRng,
        &mut transcript,
    )
    .expect("prover should not fail");

    end_timer!(timer);

    let proof = transcript.finalize();

    let strategy = SingleStrategy::new(&params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);

    let timer = start_timer!(|| "verify proof");
    // verify_proof(
    //     &params,
    //     &vk_for_verify,
    //     strategy,
    //     &[&[instance.as_slice()]],
    //     &mut transcript,
    // )
    // .unwrap();
    assert!(verify_proof::<
        KZGCommitmentScheme<Bn256>,
        VerifierGWC<'_, Bn256>,
        Challenge255<G1Affine>,
        Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
        SingleStrategy<'_, Bn256>,
    >(
        &params,
        pk.get_vk(),
        strategy,
        &[&instance_refs],
        &mut transcript
    )
    .is_ok());

    end_timer!(timer);

    // let prover = match MockProver::<Fr>::run(20, &circuit, instance) {
    //     Ok(prover) => prover,
    //     Err(e) => panic!("{e:#?}"),
    // };

    // assert_eq!(prover.verify(), Ok(()));

}

#[test]
fn test_e2e() {
    let mut g1 = G1Affine::random(&mut OsRng);
    let sk = Fr::random(&mut OsRng);
    let mut pk1 = G1Affine::from(g1.mul(sk));

    let g = (U256::from_little_endian(&g1.x.to_bytes()), U256::from_little_endian(&g1.y.to_bytes()));
    let pk = (U256::from_little_endian(&pk1.x.to_bytes()), U256::from_little_endian(&pk1.y.to_bytes()));

    let c1 = Fq12::random(&mut OsRng);

    let c2 = Fq12::random(&mut OsRng);
    
    let tag = c1 * c2;


    let circuit = MyFraudCircuit::<Fr, 9>{
        g,
        sk,
        pk,
        c1,
        c2,
        tag,
        _marker: PhantomData,
    };

    let k = 20;

    let public_inputs = circuit.instance();

    let prover = match MockProver::run(k, &circuit, public_inputs) {
        Ok(prover) => prover,
        Err(e) => panic!("{e:#?}"),
    };
    prover.assert_satisfied_par();
    prover.verify();
}

