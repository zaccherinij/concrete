use crate::specification::entities::markers::seal::EntityRepresentationMarkerSealed;
use crate::specification::entities::markers::EntityRepresentationMarker;

#[derive(Clone, Debug)]
pub struct CpuStandard32;
impl EntityRepresentationMarkerSealed for CpuStandard32 {}
impl EntityRepresentationMarker for CpuStandard32 {}

#[derive(Clone, Debug)]
pub struct CpuStandard64;
impl EntityRepresentationMarkerSealed for CpuStandard64 {}
impl EntityRepresentationMarker for CpuStandard64 {}

#[derive(Clone, Debug)]
pub struct CpuFourier32;
impl EntityRepresentationMarkerSealed for CpuFourier32 {}
impl EntityRepresentationMarker for CpuFourier32 {}

#[derive(Clone, Debug)]
pub struct CpuFourier64;
impl EntityRepresentationMarkerSealed for CpuFourier64 {}
impl EntityRepresentationMarker for CpuFourier64 {}
