# SIGNER

A playground to explore zig. The goal of this project is to be able to sign data using a QES from a web context.

For example a web app that needs the user to sign a string should be able to POST the base64-encoded string to ```http://127.0.0.1:8090/sign``` like so:
```
{"content":"dGV4dA=="}
```
This should result in a response with a base64-encoded p7s in one of the fields:
```
{
    "version":"1.0",
    "signatureType":"signature",
    "signature":"MIIJWgYJKo...",
    "status":"ok",
    "reasonCode":200,
    "reasonText":"Signed OK",
    "errorCode":0
}
```

In order to achieve this a local web server is started. The server processes incoming sign requests and presents the user with a UI to pick a certificate and enter the PIN. Once signing is complete the signed output is returned to the caller.

Under the hood once the sign request comes in some common pkcs11 lib locations are scanned and each available lib is instantiated. All available signing certificates are gathered and presented to the user. The input is signed using the chosen certificate and PIN and the signed output is returned to the caller. It should be possible to sign raw data, sha256 hashes of data or xml documents and the output is either a pkcs7 structure or a signed XML (using xmldsig) depending on the input.

It should be possible to hardcode the lib that will be used in some sort of config. Additionaly there should be a way to sign a lot of separate items without asking for a PIN every time.

***Progress:***
 - [x] pkcs11 is ready
 - [x] asn1 encoder/decoder works for the purposes of this project
 - [x] pkcs7 generation is ready
 - [x] xmldsig generation is ready
 - [x] webui is functional
 - [x] web server is working
 - [x] custom lib location can be hardcoded using a file named lib in cwd
 - [x] sessions are implemented using selectSigner and clearSigner - no PIN required for an active session
 - [ ] test with more pkcs11 providers
 - [ ] test on more machines

***Caveats:***
 - webUI is used for the UI for simplicity - future versions may move to nuklear or imgui
 - xml c14n algos are not implemented properly - they work for small documents with no extra namespaces
 - I have no experience with low level languages - this experiment is likely full of anti-patterns and buggy code
