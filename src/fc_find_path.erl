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
    {Ep1, endpoint, #{<<"ip">> := #{value := Ip1Bin}}} = hd(VerticesEdges),
    {ok, Ip1} = inet:parse_ipv4strict_address(binary_to_list(Ip1Bin)),
    {Ep2, endpoint, #{<<"ip">> := #{value := Ip2Bin}}} = lists:last(VerticesEdges),
    {ok, Ip2} = inet:parse_ipv4strict_address(binary_to_list(Ip2Bin)),
    convert_return_value(flow_rules(VerticesEdges, Graph, Ip1, Ip2)).

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

-spec flow_rules([_], digraph:graph(), inet:ip4_address(), inet:ip4_address()) -> [datapath_flow_mod()].
flow_rules(Path, Graph, Ip1, Ip2) ->
    flow_rules(Path, Graph, #{}, Ip1, Ip2).

flow_rules([{_, endpoint, _}], _Graph, FlowRulesMap, _Ip1, _Ip2) ->
    %% Nothing more to do.
    FlowRulesMap;
flow_rules([{_, endpoint, _}, connected_to | [{_, of_port, _} | _] = Tail], Graph, FlowRulesMap, Ip1, Ip2) ->
    flow_rules(Tail, Graph, FlowRulesMap, Ip1, Ip2);
flow_rules([{_, of_port, _}, connected_to | [{_, of_port, _} | _] = Tail], Graph, FlowRulesMap, Ip1, Ip2) ->
    flow_rules(Tail, Graph, FlowRulesMap, Ip1, Ip2);
flow_rules([{_, of_port, _}, connected_to | [{_, endpoint, _} | _] = Tail], Graph, FlowRulesMap, Ip1, Ip2) ->
    flow_rules(Tail, Graph, FlowRulesMap, Ip1, Ip2);
flow_rules([{Port1, of_port, _}, port_of, {_Switch, of_switch, SwitchMetadata},
	    port_of | [{Port2, of_port, _} | _] = Tail], Graph, FlowRulesMap, Ip1, Ip2) ->
    %% Add bidirectional flow rules.
    SwitchId = maps:get(value, maps:get(<<"datapath_id">>, SwitchMetadata)),
    {?OF_VERSION, ExistingRules} = maps:get(SwitchId, FlowRulesMap, {?OF_VERSION, []}),
    FromPort1 = {in_port, fc_utils:id_to_port_no(Port1)},
    ToPort2 = {apply_actions, [{output, fc_utils:id_to_port_no(Port2), no_buffer}]},
    IpTrafficThere = {
      [FromPort1,
       {ipv4_src, Ip1},
       {ipv4_dst, Ip2}],
      [ToPort2],
      [{table_id, 0},
       {cookie, unique_cookie()}]},
    ArpPacketsThere = {
      [FromPort1,
       {arp_tpa, ip_to_bin(Ip2)}],
      [ToPort2],
      [{table_id, 0},
       {cookie, unique_cookie()}]},
    FromPort2 = {in_port, fc_utils:id_to_port_no(Port2)},
    ToPort1 = {apply_actions, [{output, fc_utils:id_to_port_no(Port1), no_buffer}]},
    IpTrafficBack = {
      [FromPort2,
       {ipv4_src, Ip2},
       {ipv4_dst, Ip1}],
      [ToPort1],
      [{table_id, 0},
       {cookie, unique_cookie()}]},
    ArpPacketsBack = {
      [FromPort2,
       {arp_tpa, ip_to_bin(Ip1)}],
      [ToPort1],
      [{table_id, 0},
       {cookie, unique_cookie()}]},
    NewRules = [IpTrafficThere, ArpPacketsThere, IpTrafficBack, ArpPacketsBack],
    NewFlowRulesMap = maps:put(SwitchId, {?OF_VERSION, NewRules ++ ExistingRules}, FlowRulesMap),
    flow_rules(Tail, Graph, NewFlowRulesMap, Ip1, Ip2).

edges_between(Id1, Id2, Graph) ->
    OutEdges1 = digraph:out_edges(Graph, Id1),
    InEdges2 = digraph:in_edges(Graph, Id2),
    [Edge || Edge <- OutEdges1, lists:member(Edge, InEdges2)].

%% @doc Convert flow paths to what `dobby_oflib:publish_new_flow'
%% expects.
convert_return_value(FlowRules) ->
    %% It expects a list of tuples of the form {Dpid, {OFVersion, FlowMods}}.
    maps:to_list(FlowRules).

unique_cookie() ->
    {A,B,C} = erlang:now(),
    N = (A * 1000000 + B) * 1000000 + C,
    <<N:64>>.

ip_to_bin({A,B,C,D}) ->
    <<A:8,B:8,C:8,D:8>>.
