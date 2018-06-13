import web3.providers.rpc as rpc

def rpc_provider(host, port):
    """
    A glue function to port calls to KeepAliveRPCProvider forward
    to the current version of Web3, which uses web3.providers.rpc.HTTPProvider(),
    which has a different signature.
    """
    uri = "http://{}:{}".format(host, port)
    return rpc.HTTPProvider(endpoint_uri=uri)
