# solid-server in Node - AECO
1) install the package (further reference on https://github.com/solid/node-solid-server)
2) if you are on Windows, install WSL (Windows Subsystem for Linux) and use this as default shell
3) inside the data serving folder, run: $ sudo ../consolid-server/bin/solid-test start

To run the conSolid server, a Linux distribution needs to be used. On Windows, this requires the installation of a Windows Subsystem for Linux (WSL) (https://docs.microsoft.com/en-us/windows/wsl/install-win10), such as Debian.

When a Solid data folder has been initiated following the instructions on https://github.com/solid/node-solid-server, the server can be started by changing the default bash command 'solid start' or 'solid-test start' (when using self-signed certificates) to the path where the conSolid server is installed relative to the directory where the server will be run (e.g.: ../consolid-server/bin/solid-test start). 

Besides the standard browser-based OIDC authentication\footnote{\url{https://openid.net/connect/}}, basic authentication via Postman is enabled for development purposes. A local user may authenticate by inserting their local Solid username and password, a user whose WebID is hosted by a remote provider can do the same, but enhancing their username with their identity provider, delimited with a '.' (e.g.: bob.solid.community). Nanopublications can now be sent along as a (public) URL in the Headers or as FormData, using a key containing 'certificate'. The FormData option might be removed in the future, since GET requests officially cannot have a body attached. However, this option is still present in the current development version.
