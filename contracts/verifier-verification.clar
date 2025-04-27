;; Verifier Verification Contract
;; This contract validates legitimate credential checkers

(define-data-var admin principal tx-sender)

;; Map to store verified verifiers
(define-map verifiers principal bool)

;; Error codes
(define-constant ERR-NOT-AUTHORIZED u100)
(define-constant ERR-ALREADY-REGISTERED u101)
(define-constant ERR-NOT-REGISTERED u102)

;; Check if caller is admin
(define-private (is-admin)
  (is-eq tx-sender (var-get admin)))

;; Register a new verifier
(define-public (register-verifier (verifier principal))
  (begin
    (asserts! (is-admin) (err ERR-NOT-AUTHORIZED))
    (asserts! (is-none (map-get? verifiers verifier)) (err ERR-ALREADY-REGISTERED))
    (map-set verifiers verifier true)
    (ok true)))

;; Remove a verifier
(define-public (remove-verifier (verifier principal))
  (begin
    (asserts! (is-admin) (err ERR-NOT-AUTHORIZED))
    (asserts! (is-some (map-get? verifiers verifier)) (err ERR-NOT-REGISTERED))
    (map-delete verifiers verifier)
    (ok true)))

;; Check if a principal is a verified verifier
(define-read-only (is-verified-verifier (verifier principal))
  (default-to false (map-get? verifiers verifier)))

;; Transfer admin rights
(define-public (transfer-admin (new-admin principal))
  (begin
    (asserts! (is-admin) (err ERR-NOT-AUTHORIZED))
    (var-set admin new-admin)
    (ok true)))
