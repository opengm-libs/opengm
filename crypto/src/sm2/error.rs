use thiserror;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("invalid point")]
    InvalidPoint,

    #[error("cipher hash check failed")]
    InvalidCipherHash,
    
    #[error("unknown error")]
    Unknown,
}
pub type Result<T> = core::result::Result<T, Error>;


#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_error(){
        println!("{}", Error::InvalidPoint);
    }
}