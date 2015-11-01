;;; rsa.el --- RSA crypto in Emacs Lisp -*- lexical-binding: t; -*-

;; This is free and unencumbered software released into the public domain.

;; Author: Christopher Wellons <wellons@nullprogram.com>
;; URL: https://github.com/skeeto/emacs-rsa

;;; Commentary:

;; RSA signature algorithms built on Emacs' calc.

;; Quick start:

;; (setf keypair (rsa-generate-keypair 1024))
;; (setf message "hello, world!")
;; (setf sig (rsa-sign (plist-get keypair :private) message))
;; (rsa-verify (plist-get keypair :public) message sig)

;; For large keys you may need to adjust `max-lisp-eval-depth' and
;; `max-specpdl-size', just as you would for other large calc
;; operations.

;; Time estimates (Emacs 24.4 + Core i7):

;; Keylen       Key generation   Signature generation
;; 512 bits     12 sec           3 sec
;; 1024 bits    2 min            11 sec
;; 2048 bits    29 min           1 min

;; Signature verification time is negligible.

;;; Code:

(require 'calc)
(require 'cl-lib)

(defun rsa--buffer-to-calc-hex ()
  "Return a calc number of the bytes of the current buffer."
  (let ((f (apply-partially #'format "%02x")))
    (concat "16#" (mapconcat f (buffer-string) ""))))

(defun rsa-generate-prime (bits)
  "Generate a random prime number of BITS length from /dev/urandom."
  (with-temp-buffer
    (set-buffer-multibyte nil)
    (call-process "head" "/dev/urandom" (current-buffer) nil
                  "-c" (number-to-string (/ bits 8)))
    (calc-eval "nextprime($1, 10)" nil (rsa--buffer-to-calc-hex))))

(defun rsa--inverse (a n)
  "Multiplicative inverse using extended Euclidean algorithm."
  (let ((y 0)
        (r n)
        (newy 1)
        (newr a))
    (while (calc-eval "$1 != 0" 'pred newr)
      (let ((quotient (calc-eval "$1 \\ $2" nil r newr)))
        (cl-psetf y newy
                  newy (calc-eval "$1 - $2 * $3" nil
                                  y quotient newy))
        (cl-psetf r newr
                  newr (calc-eval "$1 - $2 * $3" nil
                                  r quotient newr))))
    (when (calc-eval "$1 > 1" 'pred r)
      (error "not invertable"))
    (if (calc-eval "$1 < 0" 'pred y)
        (calc-eval "$1 + $2" nil y n)
      y)))

(defun rsa-generate-keypair (bits)
  "Generate a fresh RSA keypair plist of BITS length."
  (let* ((p (rsa-generate-prime (+ 1 (/ bits 2))))
         (q (rsa-generate-prime (+ 1 (/ bits 2))))
         (n (calc-eval "$1 * $2" nil p q))
         (i (calc-eval "($1 - 1) * ($2 - 1)" nil p q))
         (e (calc-eval "2^16+1"))
         (d (rsa--inverse e i)))
    `(:public  (:n ,n :e ,e) :private (:n ,n :d ,d))))

(defun rsa--mod-pow (base exponent modulus)
  "Modular exponentiation using right-to-left binary method."
  (let ((result 1))
    (setf base (calc-eval "$1 % $2" nil base modulus))
    (while (calc-eval "$1 > 0" 'pred exponent)
      (when (calc-eval "$1 % 2 == 1" 'pred exponent)
        (setf result (calc-eval "($1 * $2) % $3" nil result base modulus)))
      (setf exponent (calc-eval "$1 \\ 2" nil exponent)
            base (calc-eval "($1 * $1) % $2" nil base modulus)))
    result))

(defun rsa--encode-sig (number)
  "Encode signature as short string."
  (substring (calc-eval '("$1" calc-number-radix 36) nil number) 3))

(defun rsa--decode-sig (sig)
  (concat "36#" sig))

(cl-defun rsa-sign (private-key object &optional (hash-algo 'sha384))
  "Compute the base-36 signature by PRIVATE-KEY for OBJECT.
OBJECT is a buffer or string. HASH-ALGO must be a valid symbol
for the first argument of `secure-hash'."
  (let ((n (plist-get private-key :n))
        (d (plist-get private-key :d))
        (hash (concat "16#" (secure-hash hash-algo object))))
    (while (calc-eval "$1 > $2" 'pred hash n)
      (setf hash (calc-eval "$1 \\ 2" nil hash)))
    (rsa--encode-sig (rsa--mod-pow hash d n))))

(cl-defun rsa-verify (public-key object sig &optional (hash-algo 'sha384))
  "Return non-nil nil if the signature matches PUBLIC-KEY for OBJECT.
HASH-ALGO must match the algorithm used in generating the signature."
  (let ((n (plist-get public-key :n))
        (e (plist-get public-key :e))
        (hash (concat "16#" (secure-hash hash-algo object))))
    (while (calc-eval "$1 > $2" 'pred hash n)
      (setf hash (calc-eval "$1 \\ 2" nil hash)))
    (let* ((result (rsa--mod-pow (rsa--decode-sig sig) e n)))
      (calc-eval "$1 == $2" 'pred result hash))))

(cl-defun rsa--stretch-passphrase (passphrase bits &optional (iter 500000))
  "Stretch passphrase to a size of BITS over ITER hash iterations.
Currently unused."
  (with-temp-buffer
    (set-buffer-multibyte nil)
    (dotimes (_ iter)
      (setf passphrase (secure-hash 'sha512 passphrase nil nil t)))
    (dotimes (i (ceiling bits 512))
      (insert (secure-hash 'sha512 (format "%d%s" i passphrase) nil nil t)))
    (buffer-substring (point-min) (+ (point-min) (/ bits 8)))))

(provide 'rsa)

;;; rsa.el ends here
