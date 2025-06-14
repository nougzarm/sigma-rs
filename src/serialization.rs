//! Serialization and deserialization utilities for group elements and scalars.
//!
//! This module provides functions to convert group elements and scalars to and from
//! byte representations using canonical encodings.

use ff::PrimeField;
use group::{Group, GroupEncoding};

use crate::errors::Error;

/// Returns the byte size of a field element.
#[inline]
#[allow(clippy::manual_div_ceil)]
pub fn scalar_byte_size<F: PrimeField>() -> usize {
    (F::NUM_BITS as usize + 7) / 8
}

/// Serialize a group element into a byte vector.
///
/// # Inputs
/// - `element`: A reference to the group element to serialize.
///
/// # Outputs
/// - A `Vec<u8>` containing the canonical compressed byte representation of the element.
pub fn serialize_element<G: Group + GroupEncoding>(element: &G) -> Vec<u8> {
    element.to_bytes().as_ref().to_vec()
}

/// Deserialize a byte slice into a group element.
///
/// # Parameters
/// - `data`: A byte slice containing the serialized representation of the group element.
///
/// # Returns
/// - `Ok(G)`: The deserialized group element if the input is valid.
/// - `Err(Error::GroupSerializationFailure)`: If the byte slice length is incorrect or the data
///   does not represent a valid group element.
pub fn deserialize_element<G: Group + GroupEncoding>(data: &[u8]) -> Result<G, Error> {
    let element_len = G::Repr::default().as_ref().len();
    if data.len() < element_len {
        return Err(Error::GroupSerializationFailure);
    }

    let mut repr = G::Repr::default();
    repr.as_mut().copy_from_slice(&data[..element_len]);
    let ct_point = G::from_bytes(&repr);
    if ct_point.is_some().into() {
        let point = ct_point.unwrap();
        Ok(point)
    } else {
        Err(Error::GroupSerializationFailure)
    }
}

/// Serialize a scalar field element into a byte vector.
///
/// # Parameters
/// - `scalar`: A reference to the scalar field element to serialize.
///
/// # Outputs
/// - A `Vec<u8>` containing the scalar bytes in little-endian order.
pub fn serialize_scalar<G: Group>(scalar: &G::Scalar) -> Vec<u8> {
    let mut scalar_bytes = scalar.to_repr().as_ref().to_vec();
    scalar_bytes.reverse();
    scalar_bytes
}
/// Deserialize a byte slice into a scalar field element.
///
/// # Parameters
/// - `data`: A byte slice containing the serialized scalar in little-endian order.
///
/// # Returns
/// - `Ok(G::Scalar)`: The deserialized scalar if the input is valid.
/// - `Err(Error::GroupSerializationFailure)`: If the byte slice length is incorrect or the data
///   does not represent a valid scalar.
pub fn deserialize_scalar<G: Group>(data: &[u8]) -> Result<G::Scalar, Error> {
    let scalar_len = scalar_byte_size::<G::Scalar>();
    if data.len() < scalar_len {
        return Err(Error::GroupSerializationFailure);
    }

    let mut repr = <<G as Group>::Scalar as PrimeField>::Repr::default();
    repr.as_mut().copy_from_slice(&{
        let mut tmp = data[..scalar_len].to_vec();
        tmp.reverse();
        tmp
    });
    let ct_scalar = G::Scalar::from_repr(repr);
    if ct_scalar.is_some().into() {
        let scalar = ct_scalar.unwrap();
        Ok(scalar)
    } else {
        Err(Error::GroupSerializationFailure)
    }
}
