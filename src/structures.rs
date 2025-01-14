multiversx_sc::derive_imports!();
multiversx_sc::imports!();


#[derive(TypeAbi, TopEncode, TopDecode, NestedEncode, NestedDecode, Clone)]
pub struct DidDocument<M: ManagedTypeApi> {
    pub did: ManagedBuffer<M>,
    pub controller: ManagedAddress<M>,
    pub verification_methods: ManagedVec<M, VerificationMethod<M>>,
    pub authentication: ManagedVec<M, ManagedBuffer<M>>,
    pub assertion_method: ManagedVec<M, ManagedBuffer<M>>,
    pub key_agreement: ManagedVec<M, ManagedBuffer<M>>,
    pub service_endpoints: ManagedVec<M, Service<M>>,
    pub created: u64,
    pub updated: u64,
}

#[derive(TypeAbi, TopEncode, TopDecode, NestedEncode, NestedDecode, Clone, ManagedVecItem)]
pub struct VerificationMethod<M: ManagedTypeApi> {
    pub id: ManagedBuffer<M>,
    pub type_: ManagedBuffer<M>,
    pub controller: ManagedAddress<M>,
    pub public_key_multibase: ManagedBuffer<M>,
}

#[derive(TypeAbi, TopEncode, TopDecode, NestedEncode, NestedDecode, Clone, ManagedVecItem)]
pub struct Service<M: ManagedTypeApi> {
    pub id: ManagedBuffer<M>,
    pub type_: ManagedBuffer<M>,
    pub endpoint: ManagedBuffer<M>,
}

#[derive(TypeAbi, TopEncode, TopDecode, NestedEncode, NestedDecode, Clone)]
pub struct Credential<M: ManagedTypeApi> {
    pub id: ManagedBuffer<M>,
    pub issuer: ManagedAddress<M>,
    pub holder: ManagedAddress<M>,
    pub credential_type: ManagedVec<M, ManagedBuffer<M>>,
    pub schema_id: ManagedBuffer<M>,
    pub content_hash: ManagedBuffer<M>,
    pub claims: Claims<M>,
    pub issuance_date: u64,
    pub expiration_date: Option<u64>,
    pub revoked: bool,
    pub delegation_id: Option<u64>,
    pub encryption_key: ManagedBuffer<M>,
    pub proof: CredentialProof<M>,
}

#[derive(TypeAbi, TopEncode, TopDecode, NestedEncode, NestedDecode, Clone)]
pub struct Claims<M: ManagedTypeApi> {
    pub data: ManagedVec<M, Claim<M>>,
    pub merkle_root: ManagedBuffer<M>,
}

#[derive(TypeAbi, TopEncode, TopDecode, NestedEncode, NestedDecode, Clone, ManagedVecItem)]
pub struct Claim<M: ManagedTypeApi> {
    pub attribute: ManagedBuffer<M>,
    pub value: ManagedBuffer<M>,
    pub hash: ManagedBuffer<M>,
}

#[derive(TypeAbi, TopEncode, TopDecode, NestedEncode, NestedDecode, Clone)]
pub struct CredentialProof<M: ManagedTypeApi> {
    pub type_: ManagedBuffer<M>,
    pub created: u64,
    pub verification_method: ManagedBuffer<M>,
    pub signature: ManagedBuffer<M>,
}

#[derive(TypeAbi, TopEncode, TopDecode, NestedEncode, NestedDecode, Clone)]
pub struct CredentialSchema<M: ManagedTypeApi> {
    pub id: ManagedBuffer<M>,
    pub type_: ManagedBuffer<M>,
    pub attributes: ManagedVec<M, SchemaAttribute<M>>,
    pub issuer: ManagedAddress<M>,
    pub version: ManagedBuffer<M>,
}

#[derive(TypeAbi, TopEncode, TopDecode, NestedEncode, NestedDecode, Clone, ManagedVecItem)]
pub struct SchemaAttribute<M: ManagedTypeApi> {
    pub name: ManagedBuffer<M>,
    pub attribute_type: ManagedBuffer<M>,
    pub required: bool,
    pub data_type: ManagedBuffer<M>
}

#[derive(TypeAbi, TopEncode, TopDecode, NestedEncode, NestedDecode, Clone)]
pub struct Delegation<M: ManagedTypeApi> {
    pub id: u64,
    pub delegator: ManagedAddress<M>,
    pub delegate: ManagedAddress<M>,
    pub credential_types: ManagedVec<M, ManagedBuffer<M>>,
    pub valid_until: u64,
    pub revoked: bool,
}