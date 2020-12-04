use crate::error::Error;
use snow::{params::NoiseParams, resolvers::SodiumResolver, Builder, Keypair};

#[derive(Debug, Clone)]
pub enum HandshakeChoice {
    Kx,
    Kk,
}

pub fn get_noise_params(hs_choice: &HandshakeChoice) -> Result<NoiseParams, Error> {
    let noise_params: NoiseParams = match hs_choice {
        HandshakeChoice::Kk => "Noise_KK_25519_ChaChaPoly_SHA256"
            .parse()
            .map_err(|e| Error::Noise(format!("Invalid Noise Pattern: {}", e)))?,
        HandshakeChoice::Kx => "Noise_KX_25519_ChaChaPoly_SHA256"
            .parse()
            .map_err(|e| Error::Noise(format!("Invalid Noise Pattern: {}", e)))?,
    };
    Ok(noise_params)
}

/// Revault must specify the SodiumResolver to use sodiumoxide as the cryptography provider
/// when generating a static key pair for secure communication.
pub fn generate_keypair(noise_params: NoiseParams) -> Keypair {
    Builder::with_resolver(noise_params, Box::new(SodiumResolver::default()))
        .generate_keypair()
        .unwrap()
}
