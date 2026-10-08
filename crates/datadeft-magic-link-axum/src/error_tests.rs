use super::*;

#[test]
fn general_service_error_mapping_remains_stable() {
    let cases = [
        (MagicLinkServiceError::BadRequest, StatusCode::BAD_REQUEST),
        (
            MagicLinkServiceError::MagicLinkUnavailable,
            StatusCode::BAD_REQUEST,
        ),
        (
            MagicLinkServiceError::Unavailable,
            StatusCode::SERVICE_UNAVAILABLE,
        ),
        (
            MagicLinkServiceError::Internal,
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
    ];
    for (service, status) in cases {
        assert_eq!(MagicLinkHttpError::from(service).status(), status);
    }
}
