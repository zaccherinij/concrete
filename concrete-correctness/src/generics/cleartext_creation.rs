use crate::utils::RawUnsignedIntegers;
use concrete_core::specification::engines::{CleartextCreationEngine, CleartextRetrievalEngine};
use concrete_core::specification::entities::CleartextEntity;

/// A generic function testing the cleartext creation operation.
///
/// # Note:
///
/// Type parameters prefixed with `Util` are not used in the test, but are needed to generate
/// the entities that the operation will execute on.
pub fn test<
    Engine,     // The tested engine, implementing the cleartext creation trait.
    Raw,        // The raw numeric type used to create the cleartext.
    Cleartext,  // The cleartext type
    UtilEngine, // The util engine used to retrieve the raw cleartext.
>()
where
    Engine: CleartextCreationEngine<Raw, Cleartext>,
    Raw: RawUnsignedIntegers,
    Cleartext: CleartextEntity,
    UtilEngine: CleartextRetrievalEngine<Cleartext, Raw>,
{
    let mut engine = Engine::new().unwrap();
    let mut util_engine = UtilEngine::new().unwrap();

    for _ in PARAMETERS {
        let raw = Raw::uniform();
        let cleartext = engine.create_cleartext(&raw).unwrap();
        let retrieved = util_engine.retrieve_cleartext(&cleartext).unwrap();
        assert_eq!(raw, retrieved);
    }
}

/// The parameters the test is executed against.
const PARAMETERS: [(); 10] = [(); 10];
