# SIGNER

***I have no experience with low level languages - this experiment is likely full of anti-patterns and buggy code!!!***

A playground to explore zig. The goal of this project is to start a local web server which can process incoming requests to sign hashes using an QES. To do this all known locations for pkcs11 provider libs are searched and instantiated. All available devices are scanned and a list of certificates is built. Then a UI is presented to the user in order to pick a certificate and enter the corresponding PIN. Then the provided hash is signed and pkcs7 structure is returned.

***Caveats:***
 - Custom lib locations may be supported in the future by using a config file
 - webUI is used for the UI for simplicity - future versions may move to nuklear or imgui

***Progress:***
 - pkcs11 is ready (more common lib locations need to be added)
 - asn1 encoder/decoder works for the purposes of this project
 - pkcs7 generation is ready
 - webui is in progress - it is integrated but the picker is not yet functional
 - web server is not yet started
