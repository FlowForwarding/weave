-module(fc_find_path).

%% For the type dby_identifier().
-include_lib("dobby_clib/include/dobby.hrl").
%% For the type datapath_flow_mod().
-include_lib("dobby_oflib/include/dobby_oflib.hrl").

-export([path_flow_rules/2]).

%% TODO: adapt to actual protocol version
-define(OF_VERSION, 4).

-spec path_flow_rules(binary(), binary()) -> [datapath_flow_mod()].
path_flow_rules(Ep1, Ep2) ->
    {ok, Graph} = dobby_oflib:get_path(Ep1, Ep2),
    VerticesEdges = vertices_edges_path(Graph, Ep1, Ep2),

    %% Find IP and possibly netmask for the first endpoint...
    case VerticesEdges of
        [{Ep1, endpoint, #{<<"ip">> := #{value := Ip1Bin},
                           <<"netmask">> := #{value := Netmask1Bin}}} | _] ->
            {ok, Netmask1} = inet:parse_ipv4strict_address(binary_to_list(Netmask1Bin));
        [{Ep1, endpoint, #{<<"ip">> := #{value := Ip1Bin}}} | _] ->
            Netmask1 = {255, 255, 255, 255}
    end,
    {ok, Ip1} = inet:parse_ipv4strict_address(binary_to_list(Ip1Bin)),
    %% ...and for the second endpoint.
    case lists:last(VerticesEdges) of
        {Ep2, endpoint, #{<<"ip">> := #{value := Ip2Bin},
                          <<"netmask">> := #{value := Netmask2Bin}}} ->
            {ok, Netmask2} = inet:parse_ipv4strict_address(binary_to_list(Netmask2Bin));
        {Ep2, endpoint, #{<<"ip">> := #{value := Ip2Bin}}} ->
            Netmask2 = {255, 255, 255, 255}
    end,
    {ok, Ip2} = inet:parse_ipv4strict_address(binary_to_list(Ip2Bin)),
    flow_rules(VerticesEdges, Graph, {Ip1, Netmask1}, {Ip2, Netmask2}).

vertices_edges_path(Graph, Ep1, Ep2) ->
    Path = digraph:get_path(Graph, Ep1, Ep2),
    Path =/= false orelse error(no_path_found, [Graph, Ep1, Ep2]),
    vertices_edges(Path, Graph).

vertices_edges([Id], Graph) ->
    {Id, #{<<"type">> := #{value := Type}} = Metadata} = digraph:vertex(Graph, Id),
    [{Id, binary_to_atom(Type, utf8), Metadata}];
vertices_edges([Id1, Id2 | _] = [Id1 | Tail], Graph) ->
    {Id1, #{<<"type">> := #{value := Type1}} = Metadata1} = digraph:vertex(Graph, Id1),
    {Id2, #{}} = digraph:vertex(Graph, Id2),
    %% TODO: is there a nicer way to get the edge between Id1 and Id2?
    [Edge] = edges_between(Id1, Id2, Graph),
    {Edge, Id1, Id2, #{<<"type">> := #{value := EdgeType}}} = digraph:edge(Graph, Edge),
    [{Id1, binary_to_atom(Type1, utf8), Metadata1}, binary_to_atom(EdgeType, utf8)]
	++ vertices_edges(Tail, Graph).

-spec flow_rules([_], digraph:graph(),
                 {Ip1 :: inet:ip4_address(), Netmask1 :: inet:ip4_address()},
                 {Ip2 :: inet:ip4_address(), Netmask2 :: inet:ip4_address()}) -> [datapath_flow_mod()].
flow_rules(Path, Graph, Endpoint1, Endpoint2) ->
    flow_rules(Path, Graph, [], Endpoint1, Endpoint2).

flow_rules([{_, endpoint, _}], _Graph, FlowRules, _Endpoint1, _Endpoint2) ->
    %% Nothing more to do.
    FlowRules;
flow_rules([{_, endpoint, _}, connected_to | [{_, of_port, _} | _] = Tail], Graph, FlowRules, Endpoint1, Endpoint2) ->
    flow_rules(Tail, Graph, FlowRules, Endpoint1, Endpoint2);
flow_rules([{_, of_port, _}, connected_to | [{_, of_port, _} | _] = Tail], Graph, FlowRules, Endpoint1, Endpoint2) ->
    flow_rules(Tail, Graph, FlowRules, Endpoint1, Endpoint2);
flow_rules([{_, of_port, _}, connected_to | [{_, endpoint, _} | _] = Tail], Graph, FlowRules, Endpoint1, Endpoint2) ->
    flow_rules(Tail, Graph, FlowRules, Endpoint1, Endpoint2);
flow_rules([{Port1, of_port, _}, port_of, {_Switch, of_switch, SwitchMetadata},
	    port_of | [{Port2, of_port, _} | _] = Tail], Graph, FlowRules,
           Endpoint1 = {Ip1, Netmask1}, Endpoint2 = {Ip2, Netmask2}) ->
    %% Add bidirectional flow rules.
    SwitchId = maps:get(value, maps:get(<<"datapath_id">>, SwitchMetadata)),
    FromPort1 = {in_port, fc_utils:id_to_port_no(Port1)},
    ToPort2 = {apply_actions, [{output, fc_utils:id_to_port_no(Port2), no_buffer}]},
    IpTrafficThere = {
      [FromPort1,
       {ipv4_src, ip_to_bin(Ip1), ip_to_bin(Netmask1)},
       {ipv4_dst, ip_to_bin(Ip2), ip_to_bin(Netmask2)}],
      [ToPort2],
      [{table_id, 0},
       {cookie, unique_cookie()}]},
    ArpPacketsThere = {
      [FromPort1,
       {arp_tpa, ip_to_bin(Ip2), ip_to_bin(Netmask2)}],
      [ToPort2],
      [{table_id, 0},
       {cookie, unique_cookie()}]},
    FromPort2 = {in_port, fc_utils:id_to_port_no(Port2)},
    ToPort1 = {apply_actions, [{output, fc_utils:id_to_port_no(Port1), no_buffer}]},
    IpTrafficBack = {
      [FromPort2,
       {ipv4_src, ip_to_bin(Ip2), ip_to_bin(Netmask2)},
       {ipv4_dst, ip_to_bin(Ip1), ip_to_bin(Netmask1)}],
      [ToPort1],
      [{table_id, 0},
       {cookie, unique_cookie()}]},
    ArpPacketsBack = {
      [FromPort2,
       {arp_tpa, ip_to_bin(Ip1), ip_to_bin(Netmask1)}],
      [ToPort1],
      [{table_id, 0},
       {cookie, unique_cookie()}]},
    NewRules = [IpTrafficThere, ArpPacketsThere, IpTrafficBack, ArpPacketsBack],
    NewFlowRules = [{SwitchId, ?OF_VERSION, NewRule} || NewRule <- NewRules] ++ FlowRules,
    flow_rules(Tail, Graph, NewFlowRules, Endpoint1, Endpoint2).

edges_between(Id1, Id2, Graph) ->
    OutEdges1 = digraph:out_edges(Graph, Id1),
    InEdges2 = digraph:in_edges(Graph, Id2),
    [Edge || Edge <- OutEdges1, lists:member(Edge, InEdges2)].

unique_cookie() ->
    {A,B,C} = erlang:now(),
    N = (A * 1000000 + B) * 1000000 + C,
    <<N:64>>.

ip_to_bin({A,B,C,D}) ->
    <<A:8,B:8,C:8,D:8>>.
