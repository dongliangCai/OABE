use crate::util::Field;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Challenge, Circuit, ConstraintSystem, Error},
};
use snark_verifier_sdk::CircuitExt;

use crate::{
    table::EccTable,
    util::{Challenges, SubCircuit, SubCircuitConfig},
};

use super::{MyEccCircuit, MyEccCircuitConfig, MyEccCircuitConfigArgs};

impl<F: Field, const XI_0: i64> Circuit<F> for MyEccCircuit<F, XI_0> {
    type Config = (MyEccCircuitConfig<F>, Challenges<Challenge>);
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let challenges = Challenges::construct(meta);
        let challenge_exprs = challenges.exprs(meta);
        (
            MyEccCircuitConfig::new(
                meta,
                MyEccCircuitConfigArgs {
                    challenges: challenge_exprs,
                },
            ),
            challenges,
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let challenge_values = config.1.values(&layouter);
        self.synthesize_sub(&config.0, &challenge_values, &mut layouter)
    }
}
