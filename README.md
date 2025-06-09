# SIGNER

***I have no experience with low level languages - this experiment is likely full of anti-patterns and buggy code!!!***

A playground to explore zig. The goal of this project is to start a local web server which can process incoming requests to sign hashes using an QES. To do this all known locations for pkcs11 provider libs are searched and instantiated. All available devices are scanned and a list of certificates is built. Then a UI is presented to the user in order to pick a certificate and enter the corresponding PIN. Then the provided hash is signed and pkcs7 structure is returned.

***Caveats:***
 - webUI is used for the UI for simplicity - future versions may move to nuklear or imgui

***Progress:***
 - pkcs11 is ready (more common lib locations need to be added)
 - asn1 encoder/decoder works for the purposes of this project
 - pkcs7 generation is ready
 - xmldsig is flaky - the c14n algos are not implemented properly - they work for small documents with no extra namespaces
 - webui is functional
 - web server is working
 - custom lib location can be hardcoded using a file named lib in cwd

***TODO:***
 - test with more pkcs11 providers
 - test on more machines (especially windows and linux)
