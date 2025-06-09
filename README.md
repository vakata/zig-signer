# SIGNER
A playground to explore zig. The goal of this project is to start a local web server which can process incoming requests to sign hashes using an QES. To do this all known locations for pkcs11 provider libs are searched and instantiated. All available devices are scanned and a list of certificates is built. Then a UI is presented to the user in order to pick a certificate and enter the corresponding PIN. Then the provided hash is signed and pkcs7 structure is returned.

***Progress:***
 - [x] pkcs11 is ready
 - [x] asn1 encoder/decoder works for the purposes of this project
 - [x] pkcs7 generation is ready
 - [x] xmldsig generation is ready
 - [x] webui is functional
 - [x] web server is working
 - [x] custom lib location can be hardcoded using a file named lib in cwd
 - [ ] test with more pkcs11 providers
 - [ ] test on more machines

***Caveats:***
 - webUI is used for the UI for simplicity - future versions may move to nuklear or imgui
 - xml c14n algos are not implemented properly - they work for small documents with no extra namespaces
 - I have no experience with low level languages - this experiment is likely full of anti-patterns and buggy code
