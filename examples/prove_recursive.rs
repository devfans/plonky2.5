use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::witness::PartialWitness;
use plonky2::iop::witness::WitnessWrite;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use rand::Rng;

use plonky2_5::p3::air::VerifierConstraintFolder;
use plonky2_5::p3::extension::CircuitBuilderP3ExtArithmetic;
use plonky2_5::p3::serde::proof::BinomialExtensionField;
use plonky2_5::p3::utils::reverse_bits_len;

use plonky2::field::extension::Extendable;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::config::AlgebraicHasher;

use plonky2_5::common::richer_field::RicherField;
use plonky2_5::common::u32::arithmetic_u32::U32Target;
use plonky2_5::common::u32::binary_u32::CircuitBuilderBU32;
use plonky2_5::p3::CircuitBuilderP3Arithmetic;
use plonky2_5::common::u32::interleaved_u32::CircuitBuilderB32;
use plonky2_5::p3::air::Air;
use plonky2_5::p3::challenger::DuplexChallengerTarget;
use plonky2_5::p3::serde::fri::FriConfig;
use plonky2_5::p3::serde::proof::P3Config;
use plonky2_5::p3::serde::proof::P3ProofField;
use plonky2_5::p3::serde::proof::Proof;
use plonky2_5::p3::utils::log2_ceil_usize;
use plonky2_5::p3::verifier::CircuitBuilderP3Verifier;
pub const NUM_FIBONACCI_COLS: usize = 3;

pub struct FibonacciAir {}

#[repr(C)]
pub struct FibnacciCols<T> {
    a: T,
    b: T,
    c: T,
}

impl Air for FibonacciAir {
    fn name(&self) -> String {
        "Fibonacci".to_string()
    }

    fn width(&self) -> usize {
        NUM_FIBONACCI_COLS
    }

    fn eval<F: RicherField + Extendable<D>, const D: usize>(
        &self,
        folder: &mut VerifierConstraintFolder<Target>,
        cb: &mut CircuitBuilder<F, D>,
    ) {
        let local = FibnacciCols::<BinomialExtensionField<Target>> {
            a: folder.main.trace_local[0].clone(),
            b: folder.main.trace_local[1].clone(),
            c: folder.main.trace_local[2].clone(),
        };

        let next = FibnacciCols::<BinomialExtensionField<Target>> {
            a: folder.main.trace_next[0].clone(),
            b: folder.main.trace_next[1].clone(),
            c: folder.main.trace_next[2].clone(),
        };

        let local_a_plus_b = cb.p3_ext_add(local.a.clone(), local.b.clone());
        folder.assert_eq(local_a_plus_b, local.c.clone(), cb);

        let one = cb.p3_ext_one();
        folder
            .when_first_row::<F, D>()
            .assert_eq(one.clone(), local.a.clone(), cb);
        folder
            .when_first_row::<F, D>()
            .assert_eq(one.clone(), local.b.clone(), cb);

        folder
            .when_transition::<F, D>()
            .assert_eq(next.a.clone(), local.b, cb);
        folder
            .when_transition::<F, D>()
            .assert_eq(next.b, local.c, cb);
    }
}

fn main() {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = GoldilocksField;
    let config = CircuitConfig::standard_recursion_config();

    let proof_str = include_str!("../proof_fibonacci.json");
    let proof = serde_json::from_str::<P3ProofField>(proof_str).unwrap();
    // let p: Proof<GoldilocksField>;
    // unsafe { p = std::mem::transmute(proof.clone()) }
    // std::fs::write("ppp.json", serde_json::to_string(&p).unwrap()).unwrap();

    let mut builder = CircuitBuilder::<F, D>::new(config);
    let air = FibonacciAir {};

    let config = FriConfig {
        log_blowup: 1,
        num_queries: 100,
        proof_of_work_bits: 16,
    };

    let proof_target = builder.p3_verify_proof::<PoseidonHash>(proof.clone(), &air, config);

    let data = builder.build::<C>();

    let mut pw = PartialWitness::new();

    let p: Proof<GoldilocksField>;
    unsafe { p = std::mem::transmute(proof) }

    proof_target.set_witness::<F, D, _>(&mut pw, &p);

    let start_time = std::time::Instant::now();
    let proof = data.prove(pw).unwrap();
    {
        let proof_bytes = bincode::serialize(&proof).expect("Failed to serialize proof");
        println!("Proof size: {} bytes", proof_bytes.len());
    }
    let duration_ms = start_time.elapsed().as_millis();
    std::fs::write("proof.json", serde_json::to_string(&proof).unwrap()).unwrap();
    println!("demo proved in {}ms", duration_ms);
    println!("proof public_inputs: {:?}", proof.public_inputs);

    let is_verified = data.verify(proof);
    is_verified.as_ref().unwrap();
    assert!(is_verified.is_ok());
}