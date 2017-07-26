use std;
use std::ops::Deref;
use std::error::Error as StdError;
use std::convert::From;

use hex;
use openssl;
use elementtree;

#[derive(Debug)]
pub struct Error {
    description : &'static str,
    cause : Option<Box<StdError>>,
}

impl From<hex::FromHexError> for Error {
    fn from(e : hex::FromHexError) -> Error {
        Error::from("error converting from hex", From::from(e))
    }
}

impl From<std::io::Error> for Error {
    fn from(e : std::io::Error) -> Error {
        Error::from("error reading/writing", From::from(e))
    }
}

impl From<elementtree::Error> for Error {
    fn from(e : elementtree::Error) -> Error {
        Error::from("XML error", From::from(e))
    }
}

impl From<openssl::error::ErrorStack> for Error {
    fn from(e : openssl::error::ErrorStack) -> Error {
        Error::from("openssl error", From::from(e))
    }
}

impl Error {
    pub fn new(desc : &'static str) -> Error {
        Error {
            description: desc,
            cause: None,
        }
    }

    fn from(desc : &'static str, err : Box<StdError>) -> Error {
        Error {
            description: desc,
            cause: Some(err)
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f : &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.description)
    }
}

impl StdError for Error {
    fn description(&self) -> &str {
        self.description
    }

    fn cause(&self) -> Option<&StdError> {
        match self.cause {
            None => None,
            Some(ref x) => Some(x.deref())
        }
    }
}
