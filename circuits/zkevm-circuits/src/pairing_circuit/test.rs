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

use super::MyEccCircuit;

#[test]
fn test_pairing_circuit() {
    // let alpha = Fr::random(OsRng);
    // let beta = Fr::random(OsRng);

    // let random_fq12 = Fq12::random(OsRng);

    // let point_p = G1Affine::from(G1Affine::generator() * alpha);

    // let point_q = G2Affine::from(G2Affine::generator() * beta);

    // let point_s = G1Affine::from(G1Affine::generator() * alpha * beta);

    // let point_t = G2Affine::generator();
    
    let n = 2;

    let mut ws = vec![];
    let mut c_points = vec![];
    let mut d_points = vec![];
    let mut r_points = vec![];

    for i in 0..n {
        ws.push(Fr::random(&mut OsRng));
        c_points.push(G1Affine::random(&mut OsRng));
        d_points.push(G1Affine::random(&mut OsRng));
        r_points.push(G2Affine::from(G2::random(&mut OsRng)));
    }

    let l_point = G2Affine::from(G2::random(&mut OsRng));
    

    let c_p_point = G1Affine::random(&mut OsRng);
    let r_p_point = G2Affine::from(G2::random(&mut OsRng));

    let c_w_i = ws.iter().zip(c_points.iter()).map(|(wi,ci)| G1Affine::from(ci.mul(wi))).collect::<Vec<_>>();

    let d_w_i = ws.iter().zip(d_points.iter()).map(|(wi,di)| G1Affine::from(di.mul(wi))).collect::<Vec<_>>();

    
    let mut result = pairing(&c_w_i[0], &l_point) + pairing(&d_w_i[0], &r_points[0]);

    for i in 1..n {
        result += pairing(&c_w_i[i], &l_point) + pairing(&d_w_i[i], &r_points[i]);
    }

    result += pairing(&c_p_point, &r_p_point);

    // let mut c_w = c_w_i[0];
    // for i in 1..c_w_i.len() {
    //     println!("c_w_{i} :{:?}", c_w_i[i]);
    //     c_w = G1Affine::from(c_w + c_w_i[i]);
    // }
    // println!("c_w:{:?}", c_w);
    // let mut result = pairing(&c_w, &l_point);

    // for i in 0..n {
    //     result += pairing(&d_w_i[i], &r_points[i]);
    // }
    // result += pairing(&c_p_point, &r_p_point);

    let mut p1s = vec![];
    let mut p2s = vec![];

    // let ti = pairing(&point_p, &point_q);

    println!("real result:{:?}", result);

    for i in 0..n {
        p1s.push((U256::from_little_endian(&c_points[i].x.to_bytes()), U256::from_little_endian(&c_points[i].y.to_bytes())));
        p1s.push((U256::from_little_endian(&d_points[i].x.to_bytes()), U256::from_little_endian(&d_points[i].y.to_bytes())));
        let g2_x0 = U256::from_little_endian(&r_points[i].x.c1.to_bytes());
        let g2_x1 = U256::from_little_endian(&r_points[i].x.c0.to_bytes());
        let g2_y0 = U256::from_little_endian(&r_points[i].y.c1.to_bytes());
        let g2_y1 = U256::from_little_endian(&r_points[i].y.c0.to_bytes());
        p2s.push((g2_x0, g2_x1, g2_y0, g2_y1));
    }

    let g2_x0 = U256::from_little_endian(&l_point.x.c1.to_bytes());
    let g2_x1 = U256::from_little_endian(&l_point.x.c0.to_bytes());
    let g2_y0 = U256::from_little_endian(&l_point.y.c1.to_bytes());
    let g2_y1 = U256::from_little_endian(&l_point.y.c0.to_bytes());
    let p4 = (g2_x0, g2_x1, g2_y0, g2_y1);

    let ct = (U256::from_little_endian(&c_p_point.x.to_bytes()), U256::from_little_endian(&c_p_point.y.to_bytes()));

    let g2_x0 = U256::from_little_endian(&r_p_point.x.c1.to_bytes());
    let g2_x1 = U256::from_little_endian(&r_p_point.x.c0.to_bytes());
    let g2_y0 = U256::from_little_endian(&r_p_point.y.c1.to_bytes());
    let g2_y1 = U256::from_little_endian(&r_p_point.y.c0.to_bytes());
    let tk = (g2_x0, g2_x1, g2_y0, g2_y1);


    let circuit = MyEccCircuit::<Fr, 9>{
        p1s,
        p2s,
        ws,
        p4,
        ct,
        tk,
        ti: result.0,
        _marker: PhantomData,
    };

    let k = 22;

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
    let n = 10;

    let mut ws = vec![];
    let mut c_points = vec![];
    let mut d_points = vec![];
    let mut r_points = vec![];

    for i in 0..n {
        ws.push(Fr::random(&mut OsRng));
        c_points.push(G1Affine::random(&mut OsRng));
        d_points.push(G1Affine::random(&mut OsRng));
        r_points.push(G2Affine::from(G2::random(&mut OsRng)));
    }

    let l_point = G2Affine::from(G2::random(&mut OsRng));
    

    let c_p_point = G1Affine::random(&mut OsRng);
    let r_p_point = G2Affine::from(G2::random(&mut OsRng));

    let c_w_i = ws.iter().zip(c_points.iter()).map(|(wi,ci)| G1Affine::from(ci.mul(wi))).collect::<Vec<_>>();

    let d_w_i = ws.iter().zip(d_points.iter()).map(|(wi,di)| G1Affine::from(di.mul(wi))).collect::<Vec<_>>();

    
    let mut result = pairing(&c_w_i[0], &l_point) + pairing(&d_w_i[0], &r_points[0]);

    for i in 1..n {
        result += pairing(&c_w_i[i], &l_point) + pairing(&d_w_i[i], &r_points[i]);
    }

    result += pairing(&c_p_point, &r_p_point);

    // let mut c_w = c_w_i[0];
    // for i in 1..c_w_i.len() {
    //     println!("c_w_{i} :{:?}", c_w_i[i]);
    //     c_w = G1Affine::from(c_w + c_w_i[i]);
    // }
    // println!("c_w:{:?}", c_w);
    // let mut result = pairing(&c_w, &l_point);

    // for i in 0..n {
    //     result += pairing(&d_w_i[i], &r_points[i]);
    // }
    // result += pairing(&c_p_point, &r_p_point);

    let mut p1s = vec![];
    let mut p2s = vec![];

    // let ti = pairing(&point_p, &point_q);

    println!("real result:{:?}", result);

    for i in 0..n {
        p1s.push((U256::from_little_endian(&c_points[i].x.to_bytes()), U256::from_little_endian(&c_points[i].y.to_bytes())));
        p1s.push((U256::from_little_endian(&d_points[i].x.to_bytes()), U256::from_little_endian(&d_points[i].y.to_bytes())));
        let g2_x0 = U256::from_little_endian(&r_points[i].x.c1.to_bytes());
        let g2_x1 = U256::from_little_endian(&r_points[i].x.c0.to_bytes());
        let g2_y0 = U256::from_little_endian(&r_points[i].y.c1.to_bytes());
        let g2_y1 = U256::from_little_endian(&r_points[i].y.c0.to_bytes());
        p2s.push((g2_x0, g2_x1, g2_y0, g2_y1));
    }

    let g2_x0 = U256::from_little_endian(&l_point.x.c1.to_bytes());
    let g2_x1 = U256::from_little_endian(&l_point.x.c0.to_bytes());
    let g2_y0 = U256::from_little_endian(&l_point.y.c1.to_bytes());
    let g2_y1 = U256::from_little_endian(&l_point.y.c0.to_bytes());
    let p4 = (g2_x0, g2_x1, g2_y0, g2_y1);

    let ct = (U256::from_little_endian(&c_p_point.x.to_bytes()), U256::from_little_endian(&c_p_point.y.to_bytes()));

    let g2_x0 = U256::from_little_endian(&r_p_point.x.c1.to_bytes());
    let g2_x1 = U256::from_little_endian(&r_p_point.x.c0.to_bytes());
    let g2_y0 = U256::from_little_endian(&r_p_point.y.c1.to_bytes());
    let g2_y1 = U256::from_little_endian(&r_p_point.y.c0.to_bytes());
    let tk = (g2_x0, g2_x1, g2_y0, g2_y1);


    let circuit = MyEccCircuit::<Fr, 9>{
        p1s,
        p2s,
        ws,
        p4,
        ct,
        tk,
        ti: result.0,
        _marker: PhantomData,
    };

    let k = 22;

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

    let prev_snark = gen_snark_shplonk(&params, &pk, circuit, &mut OsRng, None::<String>).unwrap();

    //compression
    // let k1 = 22;
    // let params1 = ParamsKZG::<Bn256>::setup(k1, OsRng);
    // let circuit = CompressionCircuit::new(
    //     params1,
    //     prev_snark,
    //     false,
    //     &mut OsRng,
    // );
}

#[test]
fn test_ecc_add() {
    let c_points = G1Affine::random(&mut OsRng);
    let d_points = G1Affine::random(&mut OsRng);
    let l1_point = G2Affine::from(G2::random(&mut OsRng));
    let l2_point = G2Affine::from(G2::random(&mut OsRng));

    let pairing1 = pairing(&c_points, &l1_point) - pairing(&d_points, &l2_point);

    let neg_d_point = -d_points;
    let pairing2 = pairing(&c_points, &l1_point) + pairing(&neg_d_point, &l2_point);

    assert_eq!(pairing1, pairing2);

}
