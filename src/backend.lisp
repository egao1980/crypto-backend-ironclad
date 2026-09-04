(in-package #:crypto-backend-ironclad)

(defclass ironclad-crypto-backend (crypto-protocol:crypto-backend
                                   secrets-protocol:secrets-backend)
  ()
  (:documentation "Ironclad implementation of crypto-protocol + secrets-protocol."))

(defun make-ironclad-crypto-backend ()
  (make-instance 'ironclad-crypto-backend))

(defun use-ironclad-crypto-backend ()
  "Bind both *CRYPTO-BACKEND* and *SECRETS-BACKEND* to one Ironclad instance."
  (let ((b (make-ironclad-crypto-backend)))
    (setf crypto-protocol:*crypto-backend* b
          secrets-protocol:*secrets-backend* b)
    b))

(defun %simple (v)
  (coerce v '(simple-array (unsigned-byte 8) (*))))

(defun %digest-name (algorithm)
  (or (find algorithm (ironclad:list-all-digests) :test #'string-equal)
      (error 'crypto-protocol:crypto-unsupported
             :message (format nil "unsupported digest ~s" algorithm))))

(defun %aead-name (algorithm)
  (ecase algorithm
    ((:aes-gcm :gcm) :gcm)
    ((:eax) :eax)))

(defmethod crypto-protocol:backend-digest ((backend ironclad-crypto-backend) algorithm data
                                           &key (start 0) end)
  (declare (ignore backend))
  (ironclad:digest-sequence (%digest-name algorithm) data
                            :start start :end (or end (length data))))

(defmethod crypto-protocol:backend-hmac ((backend ironclad-crypto-backend) algorithm key data
                                         &key (start 0) end)
  (declare (ignore backend))
  (let ((mac (ironclad:make-hmac (%simple key) (%digest-name algorithm)))
        (end (or end (length data))))
    (ironclad:update-hmac mac data :start start :end end)
    (ironclad:hmac-digest mac)))

(defmethod crypto-protocol:make-hasher ((backend ironclad-crypto-backend) algorithm)
  (declare (ignore backend))
  (ironclad:make-digest (%digest-name algorithm)))

(defmethod crypto-protocol:make-mac-ctx ((backend ironclad-crypto-backend) algorithm key)
  (declare (ignore backend))
  (ironclad:make-hmac (%simple key) (%digest-name algorithm)))

(defmethod crypto-protocol:update! (ctx data &key (start 0) end)
  (let ((end (or end (length data))))
    (if (typep ctx 'ironclad:hmac)
        (ironclad:update-hmac ctx data :start start :end end)
        (ironclad:update-digest ctx data :start start :end end)))
  ctx)

(defmethod crypto-protocol:finalize (ctx)
  (if (typep ctx 'ironclad:hmac)
      (ironclad:hmac-digest ctx)
      (ironclad:produce-digest ctx)))

(defun %fresh-nonce (nbytes)
  (secrets-protocol:random-bytes nbytes))

(defmethod crypto-protocol:backend-aead-encrypt
    ((backend ironclad-crypto-backend) algorithm key plaintext &key nonce aad)
  (declare (ignore backend))
  (let* ((aead (%aead-name algorithm))
         (key (%simple key))
         (nonce (%simple (or nonce (%fresh-nonce crypto-protocol:+seal-nonce-length+))))
         (pt (%simple plaintext))
         (mode (ironclad:make-authenticated-encryption-mode
                aead :cipher-name :aes :key key :initialization-vector nonce))
         (ct (if aad
                 (ironclad:encrypt-message mode pt :associated-data (%simple aad))
                 (ironclad:encrypt-message mode pt)))
         (tag (ironclad:produce-tag mode)))
    (values ct nonce tag)))

(defmethod crypto-protocol:backend-aead-decrypt
    ((backend ironclad-crypto-backend) algorithm key ciphertext &key nonce tag aad)
  (declare (ignore backend))
  (unless (and nonce tag)
    (error 'crypto-protocol:crypto-key-error
           :message "aead-decrypt requires :nonce and :tag"))
  (let* ((aead (%aead-name algorithm))
         (key (%simple key))
         (nonce (%simple nonce))
         (tag (%simple tag))
         (ct (%simple ciphertext))
         (mode (ironclad:make-authenticated-encryption-mode
                aead :cipher-name :aes :key key
                :initialization-vector nonce :tag tag)))
    (handler-case
        (if aad
            (ironclad:decrypt-message mode ct :associated-data (%simple aad))
            (ironclad:decrypt-message mode ct))
      (ironclad:bad-authentication-tag ()
        (error 'crypto-protocol:crypto-authentication-error
               :message "AEAD authentication tag mismatch")))))

;;; ---------------------------------------------------------------------------
;;; Signatures (Ed25519 / RSA-PSS / ECDSA P-256 / RSA-PKCS1)
;;; ---------------------------------------------------------------------------

(defparameter +sha256-digestinfo-prefix+
  #(#x30 #x31 #x30 #x0d #x06 #x09 #x60 #x86 #x48
    #x01 #x65 #x03 #x04 #x02 #x01 #x05 #x00 #x04 #x20)
  "DER DigestInfo prefix for SHA-256 (RFC 8017 / JWT RS256).")

(defun %pkcs1-v15-encode (message key-length)
  "PKCS#1 v1.5 DigestInfo encoding for SHA-256 (jose/JWS shape)."
  (let* ((digest (ironclad:digest-sequence :sha256 (%simple message)))
         (prefix +sha256-digestinfo-prefix+)
         (pad-len (max 0 (- key-length 3 (length prefix) (length digest)))))
    (concatenate '(simple-array (unsigned-byte 8) (*))
                 #(0 1)
                 (make-array pad-len :initial-element #xff
                             :element-type '(unsigned-byte 8))
                 #(0)
                 prefix
                 digest)))

(defun %rsa-modulus-octets (key)
  (ironclad:integer-to-octets
   (or (getf (ignore-errors (ironclad:destructure-private-key key)) :n)
       (getf (ironclad:destructure-public-key key) :n))))

(defun %coerce-ed25519-private (key)
  (etypecase key
    (ironclad:ed25519-private-key key)
    ((vector (unsigned-byte 8))
     (let ((seed (if (= (length key) 64) (subseq key 0 32) (%simple key))))
       (unless (= (length seed) 32)
         (error 'crypto-protocol:crypto-key-error
                :message "ed25519 private key must be 32 (or 64) octets"))
       (ironclad:make-private-key :ed25519 :x seed)))))

(defun %coerce-ed25519-public (key)
  (etypecase key
    (ironclad:ed25519-public-key key)
    (ironclad:ed25519-private-key
     (ironclad:make-public-key :ed25519 :y (ironclad:ed25519-key-y key)))
    ((vector (unsigned-byte 8))
     (unless (= (length key) 32)
       (error 'crypto-protocol:crypto-key-error
              :message "ed25519 public key must be 32 octets"))
     (ironclad:make-public-key :ed25519 :y (%simple key)))))

(defun %normalize-sign-algorithm (algorithm)
  (or (cdr (assoc algorithm
                  '((:ed25519 . :ed25519)
                    (:eddsa . :ed25519)
                    (:rsa-pss-sha256 . :rsa-pss-sha256)
                    (:ps256 . :rsa-pss-sha256)
                    (:ecdsa-p256-sha256 . :ecdsa-p256-sha256)
                    (:es256 . :ecdsa-p256-sha256)
                    (:secp256r1 . :ecdsa-p256-sha256)
                    (:rsa-pkcs1-sha256 . :rsa-pkcs1-sha256)
                    (:rs256 . :rsa-pkcs1-sha256))
                  :test #'eq))
      (error 'crypto-protocol:crypto-unsupported
             :message (format nil "unsupported signature algorithm ~s" algorithm))))

(defmethod crypto-protocol:backend-generate-key-pair
    ((backend ironclad-crypto-backend) algorithm &key)
  (declare (ignore backend))
  (ecase (%normalize-sign-algorithm algorithm)
    (:ed25519
     (ironclad:generate-key-pair :ed25519))
    ((:rsa-pss-sha256 :rsa-pkcs1-sha256)
     (ironclad:generate-key-pair :rsa :num-bits 2048))
    (:ecdsa-p256-sha256
     (ironclad:generate-key-pair :secp256r1))))

(defmethod crypto-protocol:backend-sign
    ((backend ironclad-crypto-backend) algorithm key message &key)
  (declare (ignore backend))
  (ecase (%normalize-sign-algorithm algorithm)
    (:ed25519
     (ironclad:sign-message (%coerce-ed25519-private key) (%simple message)))
    (:rsa-pss-sha256
     (ironclad:sign-message key (%simple message) :pss :sha256))
    (:rsa-pkcs1-sha256
     (let ((encoded (%pkcs1-v15-encode message (length (%rsa-modulus-octets key)))))
       (ironclad:sign-message key encoded)))
    (:ecdsa-p256-sha256
     (ironclad:sign-message key (ironclad:digest-sequence :sha256 (%simple message))))))

(defmethod crypto-protocol:backend-verify
    ((backend ironclad-crypto-backend) algorithm key message signature &key)
  (declare (ignore backend))
  (handler-case
      (let ((ok
              (ecase (%normalize-sign-algorithm algorithm)
                (:ed25519
                 (ironclad:verify-signature (%coerce-ed25519-public key)
                                            (%simple message)
                                            (%simple signature)))
                (:rsa-pss-sha256
                 (ironclad:verify-signature key (%simple message)
                                            (%simple signature)
                                            :pss :sha256))
                (:rsa-pkcs1-sha256
                 (ironclad:verify-signature
                  key
                  (%pkcs1-v15-encode message (length (%rsa-modulus-octets key)))
                  (%simple signature)))
                (:ecdsa-p256-sha256
                 (ironclad:verify-signature
                  key
                  (ironclad:digest-sequence :sha256 (%simple message))
                  (%simple signature))))))
        (unless ok
          (error 'crypto-protocol:crypto-authentication-error
                 :message "signature verification failed"))
        t)
    (crypto-protocol:crypto-authentication-error (c)
      (error c))
    (crypto-protocol:crypto-error (c)
      (error c))
    (error (e)
      (error 'crypto-protocol:crypto-authentication-error
             :message (format nil "signature verification failed: ~A" e)))))

(use-ironclad-crypto-backend)
