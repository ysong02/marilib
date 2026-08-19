# M-AuRA Related work version for Verifying Parties

## The Network Service 
The network service plays the role of Relying Party and EDHOC Initiator.
It initiates the whole process by sending EDHOC message1 to the gateway, which is carried in beacon and broadcast in the swarm.
Once the nework service receives the attestation result from the verifier, it decides either to kick the node or allow the data exchange with the node based on the attestation result.

You can see how it works using `examples/mari_edge.py --help`.
The corresponding libraries are `marilib/marilib/marilib_edge.py` and `marilib/marilib/marilib_attest_rp.py`.

## The Verifier
`marilib/examples/mari_remote_verifier.py`
The corresponding library is `marilib/marilib/marilib_attest_verifier.py`

Verifier receives the evidence from the network service, evaluates the evidence, and generates attestation results.

## Setup and dependencies
To setup the environment, do:

```bash
$ python -m venv .venv
$ source .venv/bin/activate
(.venv) $ pip install -e .
```
