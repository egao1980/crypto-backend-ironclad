(defsystem "crypto-backend-ironclad"
  :version "0.1.1"
  :description "Ironclad backend for crypto-protocol and secrets-protocol"
  :author "egao1980"
  :license "MIT"
  :depends-on ("crypto-protocol" "secrets-protocol" "ironclad" "uuid" "babel")
  :serial t
  :pathname "src"
  :components ((:file "package")
               (:file "backend")
               (:file "secrets"))
  :in-order-to ((test-op (test-op "crypto-backend-ironclad/tests"))))

(defsystem "crypto-backend-ironclad/tests"
  :depends-on ("crypto-backend-ironclad" "ironclad" "rove")
  :pathname "tests"
  :serial t
  :components ((:file "package")
               (:file "backend-test")
               (:file "secrets-test"))
  :perform (test-op (o c)
             (unless (symbol-call :rove :run c)
               (error "tests failed for ~A" (component-name c)))))
