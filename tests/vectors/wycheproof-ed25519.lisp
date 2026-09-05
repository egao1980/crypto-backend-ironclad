(in-package #:crypto-backend-ironclad/tests)

;;; Excerpt from C2SP/wycheproof testvectors_v1/ed25519_test.json
;;; (google-wycheproof 0.9rc5, Apache-2.0). See PROVENANCE.md.

(defparameter *wycheproof-ed25519-pk*
  (ironclad:hex-string-to-byte-array
   "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa"))

(defparameter *wycheproof-ed25519-cases*
  ;; (id msg-hex sig-hex valid-p)
  '(("tc1" ""
     "d4fbdb52bfa726b44d1786a8c0d171c3e62ca83c9e5bbe63de0bb2483f8fd6cc1429ab72cafc41ab56af02ff8fcc43b99bfe4c7ae940f60f38ebaa9d311c4007"
     t)
    ("tc2" "78"
     "d80737358ede548acb173ef7e0399f83392fe8125b2ce877de7975d8b726ef5b1e76632280ee38afad12125ea44b961bf92f1178c9fa819d020869975bcbe109"
     t)
    ("tc3" "54657374"
     "7c38e026f29e14aabd059a0f2db8b0cd783040609a8be684db12f82a27774ab07a9155711ecfaf7f99f277bad0c6ae7e39d4eef676573336a5c51eb6f946b30d"
     t)
    ("tc10" "3f"
     "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
     nil)))
