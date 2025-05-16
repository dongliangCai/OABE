use crate::{
    common::{Prover, Verifier},
    config::{LayerId, INNER_DEGREE},
    utils::{gen_rng, read_env_var, load_params},
    zkevm::circuit::{SuperCircuit, TargetCircuit, },
    WitnessBlock, EvmProof, proof::dump_as_json, io::{serialize_vk, write_file}, BatchProof,
};
use std::{sync::{LazyLock, Mutex}, ops::Mul, marker::PhantomData, fs::File, path::{Path, PathBuf}, env};

use aggregator::{CompressionCircuit, extract_proof_and_instances_with_pairing_check};
use ark_std::{start_timer, end_timer};
use eth_types::U256;
use ethers_core::k256::elliptic_curve::Group;
use halo2_proofs::{arithmetic::Field, dev::MockProver, halo2curves::bn256::{pairing, Bn256, Fq12, Fr, G1Affine, G2Affine, G2}, plonk::{keygen_pk, keygen_vk}, poly::{commitment::Params, kzg::commitment::ParamsKZG}};
use rand::rngs::OsRng;
use snark_verifier_sdk::{gen_snark_shplonk, CircuitExt, gen_evm_proof_shplonk};
use zkevm_circuits::{fraud_circuit::MyFraudCircuit, pairing_circuit::MyEccCircuit, util::SubCircuit};

static INNER_PROVER: LazyLock<Mutex<Prover>> = LazyLock::new(|| {
    let params_dir = read_env_var("SCROLL_PROVER_PARAMS_DIR", "./test_params".to_string());
    let prover = Prover::from_params_dir(&params_dir, &[*INNER_DEGREE]);
    log::info!("Constructed inner-prover");

    Mutex::new(prover)
});

static INNER_VERIFIER: LazyLock<Mutex<Verifier<<SuperCircuit as TargetCircuit>::Inner>>> =
    LazyLock::new(|| {
        let mut prover = INNER_PROVER.lock().expect("poisoned inner-prover");
        let params = prover.params(*INNER_DEGREE).clone();

        let inner_id = LayerId::Inner.id().to_string();
        let pk = prover.pk(&inner_id).expect("Failed to get inner-prove PK");
        let vk = pk.get_vk().clone();

        let verifier = Verifier::new(params, vk);
        log::info!("Constructed inner-verifier");

        Mutex::new(verifier)
    });

pub fn inner_prove(test: &str, witness_block: &WitnessBlock) {
    log::info!("{test}: inner-prove BEGIN");

    let mut prover = INNER_PROVER.lock().expect("poisoned inner-prover");

    let rng = gen_rng();
    let snark = prover
        .gen_inner_snark::<SuperCircuit>("inner", rng, witness_block)
        .unwrap_or_else(|err| panic!("{test}: failed to generate inner snark: {err}"));
    log::info!("{test}: generated inner snark");

    let verifier = INNER_VERIFIER.lock().expect("poisoned inner-verifier");

    let verified = verifier.verify_snark(snark);
    assert!(verified, "{test}: failed to verify inner snark");

    log::info!("{test}: inner-prove END");
}

#[test]
pub fn oabe_prove () {
    let n = 5;

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

    let instance = circuit.instance();

    // println!("begin mock prove");    
    // let mock_prover = MockProver::<Fr>::run(k, &circuit, instance.clone()).unwrap();
    // mock_prover.assert_satisfied_par();

    // println!("finish mock prove");

    std::env::set_var("COMPRESSION_CONFIG", "../aggregator/configs/compression_wide.config");

    let inner_k = 19;

    let outer_k = 23;

    let timer = start_timer!(|| format!("load params with K = {} and {}", inner_k, outer_k));

    let params_inner = load_params("./src/test/params19", inner_k, None).unwrap();

    let params_outer = load_params("./src/test/params23", outer_k, None).unwrap();

    end_timer!(timer);

    // let timer = start_timer!(|| format!("downsize params"));
    //  // let mut params = ParamsKZG::<Bn256>::setup(k, OsRng);
    // let mut params_outer = params_24.clone();
    // let mut params_inner = params_24.clone();

    // params_outer.downsize(23);
    // params_inner.downsize(22);
    // end_timer!(timer);

    let timer = start_timer!(|| "build vk");
    let vk = keygen_vk(&params_inner, &circuit).expect("keygen_vk should not fail");

    let current_dir = env::current_dir().unwrap();
    let mut path = PathBuf::from(current_dir);
    write_file(&mut path, "vk", &serialize_vk(&vk));
    end_timer!(timer);

    let timer = start_timer!(|| "build pk");
    let pk = keygen_pk(&params_inner, vk, &circuit).expect("keygen_pk should not fail");

    end_timer!(timer);

    let timer = start_timer!(|| "generate inner snark");
    let prev_snark = gen_snark_shplonk(&params_inner, &pk, circuit, &mut OsRng, None::<String>).unwrap();

    println!("generate oabe snark");
    end_timer!(timer);


    // extract_proof_and_instances_with_pairing_check(
    //     &params_outer,
    //     &[prev_snark.clone()],
    //     gen_rng(),
    // ).unwrap();

    println!("finish out pairing check");

    //compression
    let comp_circuit = CompressionCircuit::new(
        &params_outer,
        prev_snark,
        false,
        &mut OsRng,
    ).unwrap();

    let timer = start_timer!(|| "build vk1");
    let vk1 = keygen_vk(&params_outer, &comp_circuit).expect("keygen_vk should not fail");

    let current_dir = env::current_dir().unwrap();
    let mut path = PathBuf::from(current_dir);
    write_file(&mut path, "vk1", &serialize_vk(&vk1));

    end_timer!(timer);

    let timer = start_timer!(|| "build pk1");
    let pk1 = keygen_pk(&params_outer, vk1, &comp_circuit).expect("keygen_pk should not fail");

    end_timer!(timer);

    // let timer = start_timer!(|| "generate outer snark");

    // let snark = gen_snark_shplonk(&params_outer, &pk1, comp_circuit.clone(), &mut OsRng, None::<String>).unwrap();

    // end_timer!(timer);

    let timer = start_timer!(|| "generate evm proof");

    let instances = comp_circuit.instances();
    let num_instance = comp_circuit.num_instance();
    let proof = gen_evm_proof_shplonk(&params_outer, &pk1, comp_circuit, instances.clone(), &mut OsRng);
    let evm_proof = EvmProof::new(proof, &instances, num_instance, Some(&pk1)).unwrap();
    println!("Got final compression thin EVM proof");
    end_timer!(timer);

    let timer = start_timer!(|| "dump batch proof");
    let batch_proof = BatchProof::from(evm_proof.proof.clone());
    batch_proof.dump("./attr5_no_outer", "agg").unwrap();
    end_timer!(timer);


    // if read_env_var("SCROLL_PROVER_DUMP_YUL", false) {
    //     println!("gen_evm_verifier");
    //     crate::evm::gen_evm_verifier::<CompressionCircuit>(&params, pk1.get_vk(), &evm_proof, Some("./test/evm_verifier"));
    // }
    let timer = start_timer!(|| "gen_evm_verifier");
    crate::evm::gen_evm_verifier::<CompressionCircuit>(&params_outer, pk1.get_vk(), &evm_proof, Some("./attr5_no_outer"));
    end_timer!(timer);

    println!("finish prove of attr number:{:?}", n);
}


// #[test]
// pub fn fraud_oabe_prove () {
//     let mut g1 = G1Affine::random(&mut OsRng);
//     let sk = Fr::random(&mut OsRng);
//     let mut pk1 = G1Affine::from(g1.mul(sk));

//     let g = (U256::from_little_endian(&g1.x.to_bytes()), U256::from_little_endian(&g1.y.to_bytes()));
//     let pk = (U256::from_little_endian(&pk1.x.to_bytes()), U256::from_little_endian(&pk1.y.to_bytes()));

//     let c1 = Fq12::random(&mut OsRng);

//     let c2 = Fq12::random(&mut OsRng);
    
//     let tag = c1 * c2;


//     let circuit = MyFraudCircuit::<Fr, 9>{
//         g,
//         sk,
//         pk,
//         c1,
//         c2,
//         tag,
//         _marker: PhantomData,
//     };

//     let instance = circuit.instance();

//     // println!("begin mock prove");    
//     // let mock_prover = MockProver::<Fr>::run(k, &circuit, instance.clone()).unwrap();
//     // mock_prover.assert_satisfied_par();

//     // println!("finish mock prove");

//     std::env::set_var("COMPRESSION_CONFIG", "../aggregator/configs/compression_wide.config");

//     let inner_k = 14;

//     let outer_k = 23;

//     let timer = start_timer!(|| format!("load params with K = {} and {}", inner_k, outer_k));

//     let params_inner = load_params("./src/test/params14", inner_k, None).unwrap();

//     let params_outer = load_params("./src/test/params23", outer_k, None).unwrap();

//     end_timer!(timer);

//     // let timer = start_timer!(|| format!("downsize params"));
//     //  // let mut params = ParamsKZG::<Bn256>::setup(k, OsRng);
//     // let mut params_outer = params_24.clone();
//     // let mut params_inner = params_24.clone();

//     // params_outer.downsize(23);
//     // params_inner.downsize(22);
//     // end_timer!(timer);

//     let timer = start_timer!(|| "build vk");
//     let vk = keygen_vk(&params_inner, &circuit).expect("keygen_vk should not fail");

//     let current_dir = env::current_dir().unwrap();
//     let mut path = PathBuf::from(current_dir);
//     write_file(&mut path, "vk", &serialize_vk(&vk));
//     end_timer!(timer);

//     let timer = start_timer!(|| "build pk");
//     let pk = keygen_pk(&params_inner, vk, &circuit).expect("keygen_pk should not fail");

//     end_timer!(timer);

//     let timer = start_timer!(|| "generate proof");
//     let prev_snark = gen_snark_shplonk(&params_inner, &pk, circuit.clone(), &mut OsRng, None::<String>).unwrap();
//     println!("generate proof");
//     end_timer!(timer);

//     //compression
//     let comp_circuit = CompressionCircuit::new(
//         &params_outer,
//         prev_snark,
//         false,
//         &mut OsRng,
//     ).unwrap();

//     let timer = start_timer!(|| "build vk1");
//     let vk1 = keygen_vk(&params_outer, &comp_circuit).expect("keygen_vk should not fail");

//     let current_dir = env::current_dir().unwrap();
//     let mut path = PathBuf::from(current_dir);
//     write_file(&mut path, "vk1", &serialize_vk(&vk1));

//     end_timer!(timer);

//     let timer = start_timer!(|| "build pk1");
//     let pk1 = keygen_pk(&params_outer, vk1, &comp_circuit).expect("keygen_pk should not fail");

//     end_timer!(timer);

//     let timer = start_timer!(|| "generate evm proof");

//     let instances = comp_circuit.instances();
//     let num_instance = comp_circuit.num_instance();
//     let proof = gen_evm_proof_shplonk(&params_outer, &pk1, comp_circuit, instances.clone(), &mut OsRng);


//     let evm_proof = EvmProof::new(proof, &instances, num_instance, Some(&pk1)).unwrap();
//     println!("Got final compression thin EVM proof");
//     end_timer!(timer);

//     let timer = start_timer!(|| "dump batch proof");
//     let batch_proof = BatchProof::from(evm_proof.proof.clone());
//     batch_proof.dump("./fraud", "agg").unwrap();
//     end_timer!(timer);


//     // if read_env_var("SCROLL_PROVER_DUMP_YUL", false) {
//     //     println!("gen_evm_verifier");
//     //     crate::evm::gen_evm_verifier::<CompressionCircuit>(&params, pk1.get_vk(), &evm_proof, Some("./test/evm_verifier"));
//     // }
//     let timer = start_timer!(|| "gen_evm_verifier");
//     // crate::evm::gen_evm_verifier::<CompressionCircuit>(&params_outer, pk1.get_vk(), &evm_proof, Some("./fraud"));
//     crate::evm::gen_evm_verifier::<MyFraudCircuit::<Fr, 9>>(&params_outer, pk1.get_vk(), &evm_proof, Some("./fraud"));
//     end_timer!(timer);
// }