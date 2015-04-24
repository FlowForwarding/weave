# Utilities for weave

Helpful utilities for using weave and the flow compiler.

## mk_json

Convert an Erlang term file into a JSON file suitable for weave.  The Erlang
term file describes the topology in a more concise way than the JSON file.

### Erlang Term File
The possible terms are:

```
{of_switch, Id, DatapathId, [Port]}.
{endpoint, Id, Ip, Switch Port}.
{connect, Switch1, Port1, Switch2, Port2}.
{gateway_bridge, Id, Switch, Port}.
{gateway_mask, Id, Ip, NetMask, Switch, Port}.
```

The of_switch term identifies an OpenFlow switch. Id is the Switch
Identifier (e.g., "OFS1"), DatapathId is the switch's datapath
identifier, [Port] is a comma separate list of ports on that switch
(e.g., ["OFP1", "OFP2"]).

The endpoint term identifies an endpoint (e.g., host).  Id is the
endpoint's Identifier (e.g., "pi-11"), Ip is the endpoint's IP
address, and Switch and Port are the Switch Identifier and Port
connected to the endpoint.

The connect term forms a link between two switches.  Port1 on Switch1
is one end of the connection.  Port2 on Swith2 is the other end.

The gateway_bridge term creates a gateway to an external network
on Port of Switch.  Id is the gateway Identifier (e.g., "gatewqy").

The gateway_mask term creates a gateway using a network mask.  Id
is the gateway Identifier (e.g., "gateway"), Ip is the network
match (e.g., "10.33.0.0") and NetMask is the network mask
(e.g., "255.255.0.0").  The gateway is via Port on Switch.

Lines starting with % are comments.

See example_topology for a complete example.

### Running
Run mk_json from the command line with one or more Erlang Term files.
The files are concatenated together before converting to the JSON format.
mk_json writes the JSON file to stdout.

```
./mk_json TermFile ...
```

On Mac you can pretty print the resulting JSON using

```
python -m json.tool
```

For example:

```
./mk_json example_topology | python -m json.tool
```
