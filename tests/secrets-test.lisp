(in-package #:crypto-backend-ironclad/tests)

(deftest random-bytes-length
  (ok (= 16 (length (secrets-protocol:random-bytes 16))))
  (ok (not (equalp (secrets-protocol:random-bytes 8)
                   (secrets-protocol:random-bytes 8)))))

(deftest token-hex-and-urlsafe
  (let ((h (secrets-protocol:token-hex 8))
        (u (secrets-protocol:token-urlsafe 8)))
    (ok (= 16 (length h)))
    (ok (every (lambda (c) (digit-char-p c 16)) h))
    (ok (>= (length u) 10))
    (ok (not (find #\= u)))))

(deftest constant-time-equal
  (let ((a (ironclad:hex-string-to-byte-array "010203"))
        (b (ironclad:hex-string-to-byte-array "010203"))
        (c (ironclad:hex-string-to-byte-array "010204")))
    (ok (secrets-protocol:constant-time-equal a b))
    (ng (secrets-protocol:constant-time-equal a c))
    (ng (secrets-protocol:constant-time-equal a (ironclad:hex-string-to-byte-array "01")))))

(deftest uuid-v4
  (let ((u (secrets-protocol:uuid :version :v4)))
    (ok (= 36 (length u)))
    (ok (char= #\- (char u 8)))
    (ok (char= #\4 (char u 14)))
    (ok (find (char u 19) "89ab"))
    (ok (every (lambda (c) (or (char= c #\-) (digit-char-p c 16))) u))))

(deftest uuid-v4-bits-from-octets
  ;; All-ones and all-zeros input: only the version and variant bits change.
  (ok (string= "ffffffff-ffff-4fff-bfff-ffffffffffff"
               (crypto-backend-ironclad::make-uuid-v4
                (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xff))))
  (ok (string= "00000000-0000-4000-8000-000000000000"
               (crypto-backend-ironclad::make-uuid-v4
                (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))))

(deftest uuid-v4-unique
  (let ((seen (make-hash-table :test 'equal)))
    (dotimes (i 1000) (setf (gethash (secrets-protocol:uuid :version :v4) seen) t))
    (ok (= 1000 (hash-table-count seen)))))

(deftest uuid-v4-ignores-random-state
  ;; A fresh process starts from the same *RANDOM-STATE*. Replay one state
  ;; twice: the UUIDs must still differ, and the state must not advance.
  (let* ((seed (make-random-state nil))
         (a (let ((*random-state* (make-random-state seed)))
              (list (secrets-protocol:uuid :version :v4) (random most-positive-fixnum))))
         (b (let ((*random-state* (make-random-state seed)))
              (list (secrets-protocol:uuid :version :v4) (random most-positive-fixnum))))
         (untouched (let ((*random-state* (make-random-state seed)))
                      (random most-positive-fixnum))))
    (ok (string/= (first a) (first b)))
    (ok (= untouched (second a) (second b)))))

(deftest uuid-v7
  (let ((u (secrets-protocol:uuid :version :v7)))
    (ok (= 36 (length u)))
    (ok (char= #\- (char u 8)))
    (ok (char= #\7 (char u 14)))
    (ok (find (char u 19) "89ab"))
    (ok (not (string= u (secrets-protocol:uuid :version :v7))))))

(deftest password-argon2i-roundtrip
  (let* ((hash (secrets-protocol:hash-password "s3cret" :algorithm :argon2i)))
    (ok (secrets-protocol:verify-password "s3cret" hash))
    (ng (secrets-protocol:verify-password "wrong" hash))))

(deftest password-pbkdf2-roundtrip
  (let* ((hash (secrets-protocol:hash-password "s3cret" :algorithm :pbkdf2-sha256)))
    (ok (secrets-protocol:verify-password "s3cret" hash))
    (ng (secrets-protocol:verify-password "nope" hash))))

(deftest dual-backend-binding
  (ok (eq crypto-protocol:*crypto-backend* secrets-protocol:*secrets-backend*))
  (ok (typep crypto-protocol:*crypto-backend* 'crypto-backend-ironclad:ironclad-crypto-backend)))
