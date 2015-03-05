-module(fc_find_path).

-export([path_flow_rules/2]).

path_flow_rules(Ep1, Ep2) ->
    {ok, Graph} = dobby_oflib:get_path(Ep1, Ep2),
    VerticesEdges = vertices_edges_path(Graph, Ep1, Ep2),
    FlowRules = flow_rules(VerticesEdges, Graph),
    [{DpId, lists:append([TheFlowRules || {TheDpId, TheFlowRules} <- FlowRules,
					  TheDpId =:= DpId])}
     || DpId <- lists:usort(lists:map(fun({DpId, _}) -> DpId end, FlowRules))].

vertices_edges_path(Graph, Ep1, Ep2) ->
    Path = digraph:get_path(Graph, Ep1, Ep2),
    Path =/= false orelse error(no_path_found, [Graph, Ep1, Ep2]),
    vertices_edges(Path, Graph).

vertices_edges([Id], Graph) ->
    {Id, #{<<"type">> := Type} = Metadata} = digraph:vertex(Graph, Id),
    [{Id, binary_to_atom(Type, utf8), Metadata}];
vertices_edges([Id1, Id2 | _] = [Id1 | Tail], Graph) ->
    {Id1, #{<<"type">> := Type1} = Metadata1} = digraph:vertex(Graph, Id1),
    {Id2, #{}} = digraph:vertex(Graph, Id2),
    %% TODO: is there a nicer way to get the edge between Id1 and Id2?
    [Edge] = edges_between(Id1, Id2, Graph),
    {Edge, Id1, Id2, #{<<"type">> := EdgeType}} = digraph:edge(Graph, Edge),
    [{Id1, binary_to_atom(Type1, utf8), Metadata1}, binary_to_atom(EdgeType, utf8)]
	++ vertices_edges(Tail, Graph).

flow_rules([{_, endpoint, _}], _Graph) ->
    %% Nothing more to do.
    [];
flow_rules([{_, endpoint, _}, connected_to | [{_, of_port, _} | _] = Tail], Graph) ->
    flow_rules(Tail, Graph);
flow_rules([{_, of_port, _}, connected_to | [{_, of_port, _} | _] = Tail], Graph) ->
    flow_rules(Tail, Graph);
flow_rules([{_, of_port, _}, connected_to | [{_, endpoint, _} | _] = Tail], Graph) ->
    flow_rules(Tail, Graph);
flow_rules([{Port1, of_port, _}, port_of, {_Switch, of_switch, SwitchMetadata},
	    port_of | [{Port2, of_port, _} | _] = Tail], Graph) ->
    %% Add bidirectional flow rules.
    SwitchId = binary_to_list(maps:get(<<"datapath_id">>, SwitchMetadata)),
    Rule1 = {
      [{in_port, fc_utils:id_to_port_no(Port1)}],
      [{apply_actions, [{output, fc_utils:id_to_port_no(Port2), no_buffer}]}],
      []},
    Rule2 = {
      [{in_port, fc_utils:id_to_port_no(Port2)}],
      [{apply_actions, [{output, fc_utils:id_to_port_no(Port1), no_buffer}]}],
      []},
    [{SwitchId, [Rule1, Rule2]}]
	++ flow_rules(Tail, Graph).

edges_between(Id1, Id2, Graph) ->
    OutEdges1 = digraph:out_edges(Graph, Id1),
    InEdges2 = digraph:in_edges(Graph, Id2),
    [Edge || Edge <- OutEdges1, lists:member(Edge, InEdges2)].
