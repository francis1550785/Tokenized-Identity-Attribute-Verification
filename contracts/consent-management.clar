;; Consent Management Contract
;; Controls data sharing permissions

(define-data-var admin principal tx-sender)

;; Map to store user consent for attributes
(define-map user-consent
  { user: principal, verifier: principal, attribute: (string-ascii 64) }
  { granted: bool, expiry: uint })

;; Error codes
(define-constant ERR-NOT-AUTHORIZED u100)
(define-constant ERR-CONSENT-NOT-GRANTED u101)
(define-constant ERR-CONSENT-EXPIRED u102)

;; Check if caller is admin
(define-private (is-admin)
  (is-eq tx-sender (var-get admin)))

;; Grant consent for a verifier to access an attribute
(define-public (grant-consent (verifier principal) (attribute (string-ascii 64)) (expiry uint))
  (begin
    (map-set user-consent
      { user: tx-sender, verifier: verifier, attribute: attribute }
      { granted: true, expiry: expiry })
    (ok true)))

;; Revoke consent
(define-public (revoke-consent (verifier principal) (attribute (string-ascii 64)))
  (begin
    (map-set user-consent
      { user: tx-sender, verifier: verifier, attribute: attribute }
      { granted: false, expiry: u0 })
    (ok true)))

;; Check if consent is granted
(define-read-only (check-consent (user principal) (verifier principal) (attribute (string-ascii 64)))
  (let ((consent-data (map-get? user-consent { user: user, verifier: verifier, attribute: attribute })))
    (match consent-data
      data (and (get granted data) (< block-height (get expiry data)))
      false)))

;; Transfer admin rights
(define-public (transfer-admin (new-admin principal))
  (begin
    (asserts! (is-admin) (err ERR-NOT-AUTHORIZED))
    (var-set admin new-admin)
    (ok true)))
