(in-package #:crypto-backend-ironclad/tests)

;;; Excerpt from C2SP/wycheproof
;;; testvectors_v1/ecdsa_secp256r1_sha256_p1363_test.json
;;; (google-wycheproof 0.9rc5, Apache-2.0). IEEE P1363 r||s. See PROVENANCE.md.

;;; Ironclad secp256r1 :y is the encoded point (uncompressed 04||X||Y), not the y-coordinate.
(defparameter *wycheproof-p256-point*
  (ironclad:hex-string-to-byte-array
   "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e"))

(defun wycheproof-p256-public ()
  (ironclad:make-public-key :secp256r1 :y *wycheproof-p256-point*))

(defparameter *wycheproof-p256-cases*
  ;; (id msg-hex sig-hex valid-p)
  '(("tc1" "313233343030"
     "2ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e184cd60b855d442f5b3c7b11eb6c4e0ae7525fe710fab9aa7c77a67f79e6fadd76"
     t)
    ("tc2" "313233343030"
     "012ba3a8bd6b94d5ed80a6d9d1190a436ebccc0833490686deac8635bcb9bf536900b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db"
     nil)))
