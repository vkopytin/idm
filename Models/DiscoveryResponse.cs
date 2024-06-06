namespace Idm.Endpoints;

public record DiscoveryResponse(
    string issuer,
    string authorization_endpoint,
    string token_endpoint,
    IList<string> token_endpoint_auth_methods_supported,
    IList<string> token_endpoint_auth_signing_alg_values_supported,
    string? userinfo_endpoint,
    string? check_session_iframe,
    string? end_session_endpoint,
    string? jwks_uri,
    string? registration_endpoint,
    IList<string> scopes_supported,
    IList<string> response_types_supported,
    IList<string> acr_values_supported,
    IList<string> subject_types_supported,
    IList<string>? userinfo_signing_alg_values_supported,
    IList<string>? userinfo_encryption_alg_values_supported,
    IList<string> userinfo_encryption_enc_values_supported,
    IList<string> id_token_signing_alg_values_supported,
    IList<string> id_token_encryption_alg_values_supported,
    IList<string> id_token_encryption_enc_values_supported,
    IList<string> request_object_signing_alg_values_supported,
    IList<string> display_values_supported,
    IList<string> claim_types_supported,
    IList<string> claims_supported,
    bool claims_parameter_supported,
    string service_documentation,
    IList<string> ui_locales_supported
);