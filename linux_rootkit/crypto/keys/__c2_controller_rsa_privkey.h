/* 
 * The private key of the RSA keypair used to communicate with nodes in the network
 * from the control server.
 * 
 * 
 * 
 * 
 * Author: Daniel Liscinsky
 */


/*
 * We also maintain a copy of the corresponding 'public' key. This is okay since this file is only used to build the control server.
 */
#include "__c2_client_rsa_pubkey.h"



// ################################################################################
//									S E C R E T
// 
//					Keep this value secret under all circumstances!
// ################################################################################

/*
e is 65537 (0x10001)
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAo442tweTSH7v7M8wqqNqLO4GZCOiyE02jhUcgJIrty14cKxu
+5TMpmTj/UnS1iDM17LuvBwU3KkYm1NgoDue4qFv9v8p8kk9MA3JTBrrAPM3oasj
OOzKtwc+BCRsYOOuytOSgcRA3b+62G3SgHLIEVcH/vtSo/j46H5/7t3sRWVsQdUl
sgWGcEMi8MNEnk6udf3BjhWxeNI028fziBnA96s0HtRmp0ivSVLhhJviieEIBCZw
gvF3GJpsrzVL5FxAlCiYQMtsz8BFUxGZn0FIoN2YgJw0pdj2C3nqnQxcFKytEr3V
ievN1J/A4hSMYtbVNF3ryDZXUDyMnwmkcnUJTwIDAQABAoIBAGtfxPn6Ji4076xn
BUsxR1ZB2b5KSub3EfbLU0/xJnP2jRhji+TsdkJS//5cRec/11tQZDzorqWC+d2X
KltnaNLeK1Rbhh1DCcGPe3TUQy33frFLWi9X/WmVfphXlTMypqEPryI0RmWOJstJ
piWftUr0+RHjywhNPpPb4H9gAGo5s+FYBJNbfxSRvBZiBVSL/lZdA6MW+wYHahPp
CJyeBmSkfX8etQeRRAlCV1CVBDBMMSdbz3z1EUdxP0ITbyc+9avqV9FBSzynF/Yp
FA67uXutK153cuDT/Uz4Qt0aGGopA2qeG38OrbfVPDIFBP0sRMDLYWnEW/q+r9uE
NfDxTmkCgYEAzQcnaKbHcsEXI7dOafKHDeMvzxrpFSgbAnLa8gInzkP4hrZ6l2As
X/TntP7gqq/6aqp/UwEhHqK2gQ2kpjxs/TL9wVUQ8+2MBh70lP/AG7fdpIZNmGK5
udS7jqpFG5oFOVF7n+gY/7u2Ngv9miicZucPUmhzEDlCp2POjew9tVUCgYEAzDeU
TXRwRlGRLePLEmI6xFZCxqCX1d0p12h/KlGWRqELmYfol3V7vSJpkGHWuf0EAU6y
8eB8xqbqWSbAl0/3/gzx0OhgvKSSXFz3TK3VZA7/r107vB955qcVLthQFmq2IKEW
872SxzRCRmK5Jl9TPKqdValv+pJerey1Ny7eRBMCgYBRcHYG67htrKU0WqubCer7
aTKkYVwUO0n/PwAZASIunHErkXBAkMMPmogvLM6w/hXKKM9KeTheouM7f9/W6Emi
iY6iLNf/DGyCQemFBdGZMP+pSm+oCA8d8ZJOqPOqcxOAIQ2qBtdnPXizHzAs+9Sk
S0OayEJsP1JqiwqQ9TXNwQKBgQDItI8imJ+H3L6MlWaNyNDtCcJTKJ5RaC2pMWBZ
nRnOjJSz7ejggmx8dAfACQhafpqjFk+0fObk7kNAH2AE1mlq3BoFMX1xqWTXNd8v
E2G4Fy2fkkgVGfJaiDe/dIUxousgonHGV7ib43aHapuBZQqPgzdia0ZMw/IdiZiI
hZ2Y1QKBgFhAz1WIce9bOBfTc1IIFwnayYY+ldd9EXncrnvZmyy5+BY2GGILLW2G
fhPVNDyX6fxXi9H80/yKFTcRAQDRN2oOHAn5UzcGKIfiRlGGcpZZQOWBHFNRSLRT
p+onAxac9IGmcaOX/Y6lZ8VgTzv0dSd7V/XDVHsr8+qztzBEZuFm
-----END RSA PRIVATE KEY-----
*/