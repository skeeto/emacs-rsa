# RSA Cryptography in Emacs Lisp

This is an Emacs Lisp implementation of the [RSA public-key
cryptosystem][rsa]. Emacs' calc is used for big integer operations.
Keys are generated from `/dev/urandom`.

This package doesn't deal with protocols or key storage (e.g. the hard
parts). It's only math functions.

## Quick Demo

Here's an example using a (very short) 128-bit key.

~~~el
(setf message "hello, world!")

(setf keypair (rsa-generate-keypair 128))
;; => (:public  (:n "74924929503799951536367992905751084593"
;;               :e "65537")
;;     :private (:n "74924929503799951536367992905751084593"
;;               :d "36491277062297490768595348639394259869"))

(setf sig (rsa-sign (plist-get keypair :private) message))
;; => "1FA3ENRWZS66U8CKL6TT3VU0U"

(rsa-verify (plist-get keypair :public) message sig)
;; => t
~~~

Larger keys can take many minutes to generate and compute signatures.


[rsa]: https://en.wikipedia.org/wiki/RSA_(cryptosystem)
