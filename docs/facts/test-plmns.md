# Test PLMNs

Carrier facts live here, never in code. The tree is generic over MCC/MNC; only
this file names operators.

| SIM | MCC | MNC | ePDG name to try first |
|---|---|---|---|
| T-Mobile US | 310 | 260 | `epdg.epc.mnc260.mcc310.pub.3gppnetwork.org` |
| Gigs (Dumb.co), MVNO on the same network | 310 | 260 | same as above |

Both are expected to resolve through the Operator Identifier FQDN
(TS 23.003 §19.4.2.9.2). Anything beyond that — which ePDG a given SIM is
actually steered to, and whether the visited-country NAPTR applies — is a
network fact to be recorded here only after it has been observed on a real
attach, not inferred.
