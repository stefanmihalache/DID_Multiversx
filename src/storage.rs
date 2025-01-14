multiversx_sc::imports!();


use crate::structures::*;

#[multiversx_sc::module]
pub trait StorageModule {
    #[storage_mapper("admin")]
    fn admin(&self) -> SingleValueMapper<ManagedAddress<Self::Api>>;

    #[view(getDidDocument)]
    #[storage_mapper("didDocuments")]
    fn did_documents(&self, did: &ManagedBuffer) -> SingleValueMapper<DidDocument<Self::Api>>;

    #[storage_mapper("addressToDid")]
    fn address_to_did(&self, address: &ManagedAddress) -> SingleValueMapper<ManagedBuffer>;

    #[storage_mapper("credentialSchemas")]
    fn credential_schemas(&self, schema_id: &ManagedBuffer) -> SingleValueMapper<CredentialSchema<Self::Api>>;

    #[storage_mapper("credentials")]
    fn credentials(&self, id: &u64) -> SingleValueMapper<Credential<Self::Api>>;

    #[view(getNextCredentialId)]
    #[storage_mapper("nextCredentialId")]
    fn next_credential_id(&self) -> SingleValueMapper<u64>;

    #[storage_mapper("holderCredentials")]
    fn holder_credentials(&self, holder: &ManagedAddress) -> VecMapper<u64>;

    #[storage_mapper("delegations")]
    fn delegations(&self, id: &u64) -> SingleValueMapper<Delegation<Self::Api>>;

    #[storage_mapper("nextDelegationId")]
    fn next_delegation_id(&self) -> SingleValueMapper<u64>;

    #[storage_mapper("delegateToDelegations")]
    fn delegate_to_delegations(&self, delegate: &ManagedAddress) -> VecMapper<u64>;

    #[storage_mapper("issuers")]
    fn issuers(&self, address: &ManagedAddress) -> SingleValueMapper<bool>;

    #[storage_mapper("paused")]
    fn paused(&self) -> SingleValueMapper<bool>;
}