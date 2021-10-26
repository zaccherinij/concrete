use crate::utils::RawUnsignedIntegers;
use concrete_core::specification::engines::{
    CleartextVectorCreationEngine, CleartextVectorRetrievalEngine,
};
use concrete_core::specification::entities::CleartextVectorEntity;

/// A generic function testing the cleartext vector creation operation.
///
/// # Note:
///
/// Type parameters prefixed with `Util` are not used in the test, but are needed to generate
/// the entities that the operation will execute on.
pub fn test<
    Engine,          // The tested engine, implementing the cleartext vector creation trait
    Raw,             // The raw numeric type used to create the cleartext vectors.
    CleartextVector, // The cleartext vector type.
    UtilEngine,      // The util engine used to retrieve the raw slice.
>()
where
    Engine: CleartextVectorCreationEngine<Raw, CleartextVector>,
    Raw: RawUnsignedIntegers,
    CleartextVector: CleartextVectorEntity,
    UtilEngine: CleartextVectorRetrievalEngine<CleartextVector, Raw>,
{
    let mut util_engine = UtilEngine::new().unwrap();
    let mut engine = Engine::new().unwrap();

    for _ in PARAMETERS {
        let raw = Raw::uniform_vec(10);
        let cleartext = engine.create_cleartext_vector(&raw.as_slice()).unwrap();
        let retrieved = util_engine.retrieve_cleartext_vector(&cleartext).unwrap();
        assert_eq!(raw.as_slice(), retrieved);
    }
}

/// The parameters the test is executed against.
const PARAMETERS: [(); 10] = [(); 10];
