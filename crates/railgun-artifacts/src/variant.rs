//! Canonical artifact variant resolution.

use crate::ArtifactError;

/// Circuit family for artifact selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CircuitFamily {
    /// Standard joinsplit proving circuits.
    Standard,
    /// Proof of Innocence proving circuits.
    Poi,
}

/// Validated standard circuit input and output counts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StandardCircuitShape {
    n_inputs: u8,
    n_outputs: u8,
}

impl StandardCircuitShape {
    /// Creates a validated standard circuit shape.
    ///
    /// # Errors
    ///
    /// Returns an error when the input and output pair does not match the
    /// canonical supported artifact matrix.
    pub fn new(n_inputs: u8, n_outputs: u8) -> Result<Self, ArtifactError> {
        if is_supported_standard_shape(n_inputs, n_outputs) {
            Ok(Self { n_inputs, n_outputs })
        } else {
            Err(ArtifactError::UnsupportedStandardShape { n_inputs, n_outputs })
        }
    }

    /// Returns the validated input count.
    #[must_use]
    pub const fn n_inputs(self) -> u8 {
        self.n_inputs
    }

    /// Returns the validated output count.
    #[must_use]
    pub const fn n_outputs(self) -> u8 {
        self.n_outputs
    }
}

impl core::fmt::Display for StandardCircuitShape {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{:02}x{:02}", self.n_inputs, self.n_outputs)
    }
}

/// Validated POI circuit shape.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PoiCircuitShape {
    /// Small POI proof shape.
    ThreeByThree,
    /// Large POI proof shape.
    ThirteenByThirteen,
}

impl PoiCircuitShape {
    /// Creates a validated POI circuit shape.
    ///
    /// # Errors
    ///
    /// Returns an error when the requested POI shape is not one of the
    /// canonical supported variants.
    pub fn new(max_inputs: u8, max_outputs: u8) -> Result<Self, ArtifactError> {
        match (max_inputs, max_outputs) {
            (3, 3) => Ok(Self::ThreeByThree),
            (13, 13) => Ok(Self::ThirteenByThirteen),
            _ => Err(ArtifactError::UnsupportedPoiShape { max_inputs, max_outputs }),
        }
    }

    /// Returns the canonical POI input bound.
    #[must_use]
    pub const fn max_inputs(self) -> u8 {
        match self {
            Self::ThreeByThree => 3,
            Self::ThirteenByThirteen => 13,
        }
    }

    /// Returns the canonical POI output bound.
    #[must_use]
    pub const fn max_outputs(self) -> u8 {
        self.max_inputs()
    }
}

impl core::fmt::Display for PoiCircuitShape {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ThreeByThree => formatter.write_str("POI_3x3"),
            Self::ThirteenByThirteen => formatter.write_str("POI_13x13"),
        }
    }
}

/// Canonical artifact variant selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactVariant {
    /// Standard joinsplit artifact variant.
    Standard(StandardCircuitShape),
    /// POI artifact variant.
    Poi(PoiCircuitShape),
}

impl ArtifactVariant {
    /// Returns the artifact family.
    #[must_use]
    pub const fn family(self) -> CircuitFamily {
        match self {
            Self::Standard(_) => CircuitFamily::Standard,
            Self::Poi(_) => CircuitFamily::Poi,
        }
    }
}

impl core::fmt::Display for ArtifactVariant {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Standard(shape) => shape.fmt(formatter),
            Self::Poi(shape) => shape.fmt(formatter),
        }
    }
}

impl core::str::FromStr for ArtifactVariant {
    type Err = ArtifactError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        parse_artifact_variant(value)
    }
}

/// Parses a canonical artifact variant string into a typed variant.
///
/// # Errors
///
/// Returns an error when the variant string is not one of the supported canonical
/// standard or POI shapes.
pub fn parse_artifact_variant(value: &str) -> Result<ArtifactVariant, ArtifactError> {
    if value == "POI_3x3" {
        return resolve_poi_variant(3, 3);
    }
    if value == "POI_13x13" {
        return resolve_poi_variant(13, 13);
    }

    let Some((n_inputs, n_outputs)) = value.split_once('x') else {
        return Err(ArtifactError::UnknownArtifactVariant(value.to_owned()));
    };

    let Ok(n_inputs) = n_inputs.parse::<u8>() else {
        return Err(ArtifactError::UnknownArtifactVariant(value.to_owned()));
    };
    let Ok(n_outputs) = n_outputs.parse::<u8>() else {
        return Err(ArtifactError::UnknownArtifactVariant(value.to_owned()));
    };

    resolve_standard_variant(n_inputs, n_outputs)
        .map_err(|_| ArtifactError::UnknownArtifactVariant(value.to_owned()))
}

/// Resolves a canonical standard circuit artifact variant.
///
/// # Errors
///
/// Returns an error when the input and output pair is unsupported.
pub fn resolve_standard_variant(
    n_inputs: u8,
    n_outputs: u8,
) -> Result<ArtifactVariant, ArtifactError> {
    StandardCircuitShape::new(n_inputs, n_outputs).map(ArtifactVariant::Standard)
}

/// Resolves a canonical POI circuit artifact variant.
///
/// # Errors
///
/// Returns an error when the POI proof shape is unsupported.
pub fn resolve_poi_variant(
    max_inputs: u8,
    max_outputs: u8,
) -> Result<ArtifactVariant, ArtifactError> {
    PoiCircuitShape::new(max_inputs, max_outputs).map(ArtifactVariant::Poi)
}

const fn is_supported_standard_shape(n_inputs: u8, n_outputs: u8) -> bool {
    matches!((n_inputs, n_outputs), (1..=10, 1..=5) | (11..=13, 1) | (1, 10 | 13))
}

#[cfg(test)]
mod tests {
    use super::{
        ArtifactError, ArtifactVariant, PoiCircuitShape, StandardCircuitShape,
        parse_artifact_variant, resolve_poi_variant, resolve_standard_variant,
    };

    #[test]
    fn resolves_supported_standard_variants() {
        for ((n_inputs, n_outputs), expected) in [
            ((1, 1), "01x01"),
            ((10, 4), "10x04"),
            ((11, 1), "11x01"),
            ((12, 1), "12x01"),
            ((13, 1), "13x01"),
            ((1, 10), "01x10"),
            ((1, 13), "01x13"),
        ] {
            let Ok(variant) = resolve_standard_variant(n_inputs, n_outputs) else {
                panic!("expected supported standard shape {n_inputs}x{n_outputs}");
            };
            assert_eq!(variant.to_string(), expected);
        }
    }

    #[test]
    fn rejects_unsupported_standard_variants() {
        for (n_inputs, n_outputs) in [(0, 1), (1, 0), (10, 6), (11, 2), (2, 13), (14, 1)] {
            let Err(error) = resolve_standard_variant(n_inputs, n_outputs) else {
                panic!("expected unsupported standard shape {n_inputs}x{n_outputs}");
            };
            assert_eq!(error, ArtifactError::UnsupportedStandardShape { n_inputs, n_outputs });
        }
    }

    #[test]
    fn resolves_supported_poi_variants() {
        for ((max_inputs, max_outputs), expected) in [((3, 3), "POI_3x3"), ((13, 13), "POI_13x13")]
        {
            let Ok(variant) = resolve_poi_variant(max_inputs, max_outputs) else {
                panic!("expected supported POI shape {max_inputs}x{max_outputs}");
            };
            assert_eq!(variant.to_string(), expected);
        }
    }

    #[test]
    fn rejects_unsupported_poi_variants() {
        for (max_inputs, max_outputs) in [(3, 13), (13, 3), (0, 0), (4, 4)] {
            let Err(error) = resolve_poi_variant(max_inputs, max_outputs) else {
                panic!("expected unsupported POI shape {max_inputs}x{max_outputs}");
            };
            assert_eq!(error, ArtifactError::UnsupportedPoiShape { max_inputs, max_outputs });
        }
    }

    #[test]
    fn exposes_shape_metadata() {
        let Ok(standard) = StandardCircuitShape::new(10, 4) else {
            panic!("expected supported standard shape 10x4");
        };
        assert_eq!(standard.n_inputs(), 10);
        assert_eq!(standard.n_outputs(), 4);

        let Ok(poi) = PoiCircuitShape::new(13, 13) else {
            panic!("expected supported POI shape 13x13");
        };
        assert_eq!(poi.max_inputs(), 13);
        assert_eq!(poi.max_outputs(), 13);

        assert_eq!(ArtifactVariant::Standard(standard).family(), super::CircuitFamily::Standard);
        assert_eq!(ArtifactVariant::Poi(poi).family(), super::CircuitFamily::Poi);
    }

    #[test]
    fn parses_supported_variant_strings() {
        let Ok(standard) = parse_artifact_variant("01x01") else {
            panic!("expected standard variant string to parse");
        };
        let Ok(poi) = parse_artifact_variant("POI_3x3") else {
            panic!("expected poi variant string to parse");
        };

        assert_eq!(standard.to_string(), "01x01");
        assert_eq!(poi.to_string(), "POI_3x3");
    }

    #[test]
    fn rejects_unknown_variant_strings() {
        for value in ["", "poi_3x3", "abc", "11x02", "1x1x1"] {
            let Err(error) = parse_artifact_variant(value) else {
                panic!("expected invalid variant string {value} to fail");
            };
            assert_eq!(error, ArtifactError::UnknownArtifactVariant(value.to_owned()));
        }
    }
}
