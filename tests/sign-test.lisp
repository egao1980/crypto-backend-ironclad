(in-package #:crypto-backend-ironclad/tests)

(defun %flip (octets)
  (let ((out (copy-seq octets)))
    (setf (aref out 0) (logxor (aref out 0) 1))
    out))

(deftest sign-roundtrip
  (dolist (algorithm '(:ed25519 :rsa-pss-sha256 :ecdsa-p256-sha256 :rsa-pkcs1-sha256))
    (testing (string algorithm)
      (multiple-value-bind (sk pk)
          (crypto-protocol:generate-key-pair algorithm)
        (let* ((msg (ironclad:ascii-string-to-byte-array "cl-stack sign"))
               (sig (crypto-protocol:sign msg :algorithm algorithm :key sk)))
          (ok (crypto-protocol:verify msg sig :algorithm algorithm :key pk))
          (ok (signals (crypto-protocol:verify (%flip msg) sig
                                               :algorithm algorithm :key pk)
                       'crypto-protocol:crypto-authentication-error))
          (ok (signals (crypto-protocol:verify msg (%flip sig)
                                               :algorithm algorithm :key pk)
                       'crypto-protocol:crypto-authentication-error)))))))

(deftest ed25519-rfc8032-empty
  (let ((sig (crypto-protocol:sign #() :algorithm :ed25519
                                   :key *rfc8032-ed25519-seed*)))
    (ok (equalp *rfc8032-ed25519-sig* sig))
    (ok (crypto-protocol:verify #() sig :algorithm :ed25519
                                :key *rfc8032-ed25519-public*))))

(deftest ed25519-raw-octet-keys
  (multiple-value-bind (sk pk)
      (crypto-protocol:generate-key-pair :ed25519)
    (let* ((seed (ironclad:ed25519-key-x sk))
           (pub (ironclad:ed25519-key-y pk))
           (msg #(1 2 3 4))
           (sig (crypto-protocol:sign msg :algorithm :ed25519 :key seed)))
      (ok (crypto-protocol:verify msg sig :algorithm :ed25519 :key pub)))))

(deftest jwt-aliases
  (multiple-value-bind (sk pk)
      (crypto-protocol:generate-key-pair :ed25519)
    (let* ((msg #(9 8 7))
           (sig (crypto-protocol:sign msg :algorithm :eddsa :key sk)))
      (ok (crypto-protocol:verify msg sig :algorithm :eddsa :key pk)))))
