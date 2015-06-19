-module(fc_find_path).

%% For the type dby_identifier().
-include_lib("dobby_clib/include/dobby.hrl").
%% For the type datapath_flow_mod().
-include_lib("dobby_oflib/include/dobby_oflib.hrl").

-export([use_bridge_rules/1,
         path_flow_rules/2,
         hub_flow_rules/2,
         tap_flow_rules/2
        ]).

%% TODO: adapt to actual protocol version
-define(OF_VERSION, 4).

use_bridge_rules(SourceEndpoint) ->
    dby:search(
      fun(_Id, #{<<"use_bridge_rules">> := #{value := true}}, _, _) ->
              {stop, true};
         (_Id, _Metadata, _, _) ->
              {stop, false}
      end,
      false,
      SourceEndpoint,
      [breadth, {max_depth, 1}]).

-spec path_flow_rules(binary(), binary()) -> [datapath_flow_mod()].
path_flow_rules(Ep1, Ep2) ->
    {ok, Graph} = dobby_oflib:get_path(Ep1, Ep2),
    VerticesEdges = vertices_edges_path(Graph, Ep1, Ep2),

    FirstVertice = hd(VerticesEdges),
    LastVertice = lists:last(VerticesEdges),

    %% Find IP and possibly netmask for the endpoints
    case {endpoint_ip_netmask(FirstVertice), endpoint_ip_netmask(LastVertice)} of
        {{Ip1, Netmask1}, {Ip2, Netmask2}} ->

            RestOfTrafficRules =
                case {is_rest_of_traffic(FirstVertice), is_rest_of_traffic(LastVertice)} of
                    {false, false} ->
                        [];
                    {true, false} ->
                        flow_rules(VerticesEdges, Graph, {{0,0,0,0}, {0,0,0,0}}, {Ip2, Netmask2});
                    {false, true} ->
                        flow_rules(VerticesEdges, Graph, {Ip1, Netmask1}, {{0,0,0,0}, {0,0,0,0}})
                end,

            RestOfTrafficRules ++
                flow_rules(VerticesEdges, Graph, {Ip1, Netmask1}, {Ip2, Netmask2});
        %% If one or both of the endpoints don't have an IP address,
        %% use hub rules instead.
        {no_ip_address, _} ->
            hub_flow_rules(Ep1, [Ep2]);
        {_, no_ip_address} ->
            hub_flow_rules(Ep1, [Ep2])
    end.

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
    {Edge, Id1, Id2, #{<<"type">> := #{value := ActualEdgeType}}} = digraph:edge(Graph, Edge),
    EdgeType =
        case ActualEdgeType of
            <<"port_of">> ->
                %% Accept "port_of" as synonym for "part_of" for now.
                <<"part_of">>;
            _ ->
                ActualEdgeType
        end,
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
flow_rules([{Port1, of_port, _}, part_of, {SwitchId, of_switch, _SwitchMetadata},
	    part_of | [{Port2, of_port, _} | _] = Tail], Graph, FlowRules,
           Endpoint1 = {Ip1, Netmask1}, Endpoint2 = {Ip2, Netmask2}) ->
    %% Add bidirectional flow rules.
    FromPort1 = {in_port, fc_utils:id_to_port_no(Port1)},
    ToPort2 = {apply_actions, [{output, fc_utils:id_to_port_no(Port2), no_buffer}]},
    NetmaskBin1 = ip_to_bin(Netmask1),
    NetmaskBin2 = ip_to_bin(Netmask2),
    %% The priority of the rule is the length of the shortest netmask.
    %% TODO: look for guidance in the JSON file.
%%SN    Priority = {priority, min(netmask_length(NetmaskBin1), netmask_length(NetmaskBin2))},
    Priority = {priority, 51},
    IpTrafficThere = {
      [FromPort1] ++
          %% If the netmask is all zeroes, there is no point in matching anything.
          [{ipv4_src, ip_to_bin(Ip1), NetmaskBin1} || NetmaskBin1 =/= <<0,0,0,0>>] ++
          [{ipv4_dst, ip_to_bin(Ip2), NetmaskBin2} || NetmaskBin2 =/= <<0,0,0,0>>],
      [ToPort2],
      [{table_id, 0},
       Priority,
       {cookie, unique_cookie()}]},
    IpBroadcastThere = {
      [FromPort1,
       {ipv4_dst, <<255, 255, 255, 255>>}],
      %% XXX: In principle, we should broadcast this packet.
      [ToPort2],
      [{table_id, 0},
       Priority,
       {cookie, unique_cookie()}]},
    ArpPacketsThere = {
      [FromPort1,
       {eth_type,<<16#806:16>>}] ++
          [{arp_tpa, ip_to_bin(Ip2), NetmaskBin2} || NetmaskBin2 =/= <<0,0,0,0>>],
      [ToPort2],
      [{table_id, 0},
       Priority,
       {cookie, unique_cookie()}]},
    FromPort2 = {in_port, fc_utils:id_to_port_no(Port2)},
    ToPort1 = {apply_actions, [{output, fc_utils:id_to_port_no(Port1), no_buffer}]},
    IpTrafficBack = {
      [FromPort2] ++
          [{ipv4_src, ip_to_bin(Ip2), NetmaskBin2} || NetmaskBin2 =/= <<0,0,0,0>>] ++
          [{ipv4_dst, ip_to_bin(Ip1), NetmaskBin1} || NetmaskBin1 =/= <<0,0,0,0>>],
      [ToPort1],
      [{table_id, 0},
       Priority,
       {cookie, unique_cookie()}]},
    IpBroadcastBack = {
      [FromPort2,
       {ipv4_dst, <<255, 255, 255, 255>>}],
      %% XXX: ditto
      [ToPort1],
      [{table_id, 0},
       Priority,
       {cookie, unique_cookie()}]},
    ArpPacketsBack = {
      [FromPort2,
       {eth_type,<<16#806:16>>}] ++
          [{arp_tpa, ip_to_bin(Ip1), NetmaskBin1} || NetmaskBin1 =/= <<0,0,0,0>>],
      [ToPort1],
      [{table_id, 0},
       Priority,
       {cookie, unique_cookie()}]},
    NewRules = [IpTrafficThere, IpBroadcastThere, ArpPacketsThere,
                IpTrafficBack, IpBroadcastBack, ArpPacketsBack],
    NewFlowRules = [{SwitchId, ?OF_VERSION, NewRule} || NewRule <- NewRules] ++ FlowRules,
    flow_rules(Tail, Graph, NewFlowRules, Endpoint1, Endpoint2).

edges_between(Id1, Id2, Graph) ->
    OutEdges1 = digraph:out_edges(Graph, Id1),
    InEdges2 = digraph:in_edges(Graph, Id2),
    [Edge || Edge <- OutEdges1, lists:member(Edge, InEdges2)].

unique_cookie() ->
    %% Create a unique cookie for each flow rule.  erlang:now() should
    %% be unique enough.
    {A,B,C} = erlang:now(),
    N = (A * 1000000 + B) * 1000000 + C,

    %% We could just create a binary from this number:
    %% <<N:64>>
    %% but it would be nicer if it were printable.
    %% Let's use the 94 printable ASCII characters from ! to ~.
    %% The result will fit into 8 such characters until year 2163.
    encode94(N).

encode94(N) ->
    First = $!,
    Last = $~,
    Base = Last - First + 1,

    Quot = N div Base,
    Rem = N rem Base,

    Digit = First + Rem,
    case Quot of
        0 ->
            <<Digit>>;
        _ ->
            <<(encode94(Quot))/binary, Digit>>
    end.

endpoint_ip_netmask({_Ep, endpoint, #{<<"ip">> := #{value := IpBin},
                                      <<"netmask">> := #{value := NetmaskBin}}}) ->
    {ok, Netmask} = inet:parse_ipv4strict_address(binary_to_list(NetmaskBin)),
    {ok, Ip} = inet:parse_ipv4strict_address(binary_to_list(IpBin)),
    {Ip, Netmask};
endpoint_ip_netmask({_Ep, endpoint, #{<<"ip">> := #{value := IpBin}}}) ->
    Netmask = {255, 255, 255, 255},
    {ok, Ip} = inet:parse_ipv4strict_address(binary_to_list(IpBin)),
    {Ip, Netmask};
endpoint_ip_netmask({_Ep, endpoint, #{}}) ->
    %% The given endpoint has no specified IP address.
    no_ip_address.


is_rest_of_traffic({_Ep, endpoint, #{<<"rest-of-traffic">> := #{value := true}}}) ->
    true;
is_rest_of_traffic({_Ep, endpoint, #{}}) ->
    false.

ip_to_bin({A,B,C,D}) ->
    <<A:8,B:8,C:8,D:8>>.

netmask_length(NetmaskBin) ->
    netmask_length(NetmaskBin, 0).

netmask_length(<<>>, Acc) ->
    Acc;
netmask_length(<<0:1, _/bits>>, Acc) ->
    Acc;
netmask_length(<<1:1, Rest/bits>>, Acc) ->
    netmask_length(Rest, 1 + Acc).

hub_flow_rules(SourceEndpoint, TargetEndpoints) ->
    %% Create flow rules that send every packet from SourceEndpoint to
    %% each of the TargetEndpoints, and every packet from one of the
    %% TargetEndpoints to SourceEndpoints, only looking at inports and
    %% disregarding any properties of the packets.
    Paths = [begin
                  case dobby_oflib:get_path(SourceEndpoint, TargetEndpoint) of
                      {ok, Graph} ->
                          vertices_edges_path(Graph, SourceEndpoint, TargetEndpoint);
                      {error, no_path} ->
                          io:format(standard_error,
                                    "No path found between '~s' and '~s'~n",
                                    [SourceEndpoint, TargetEndpoint]),
                          error({no_path, SourceEndpoint, TargetEndpoint})
                  end
              end || TargetEndpoint <- TargetEndpoints],
    %% For each target endpoint, find where we need to install bridge
    %% rules.
    BridgeHere = lists:append(lists:map(fun bridge_points/1, Paths)),
    %% Combine them into one rule for each switch+inport combination.
    Combined = combine_bridge_points(BridgeHere),
    lists:map(fun hub_flow_rule/1, Combined).

bridge_points([{_, endpoint, _}]) ->
    %% Nothing more to do.
    [];
bridge_points([{_, endpoint, _}, connected_to | [{_, of_port, _} | _] = Tail]) ->
    bridge_points(Tail);
bridge_points([{_, of_port, _}, connected_to | [{_, of_port, _} | _] = Tail]) ->
    bridge_points(Tail);
bridge_points([{_, of_port, _}, connected_to | [{_, endpoint, _} | _] = Tail]) ->
    bridge_points(Tail);
bridge_points([{Port1, of_port, _}, part_of, {SwitchId, of_switch, _SwitchMetadata},
              part_of | [{Port2, of_port, _} | _] = Tail]) ->
    BridgeThere = {{SwitchId, Port1}, [Port2]},
    BridgeBack = {{SwitchId, Port2}, [Port1]},
    [BridgeThere, BridgeBack] ++ bridge_points(Tail).

combine_bridge_points([]) ->
    [];
combine_bridge_points([{Key = {_SwitchId, _InPort}, OutPorts} | Rest]) ->
    %% As long as there are more entries for a switch+inport
    %% combination, keep merging them into one entry.
    case lists:keytake(Key, 1, Rest) of
        {value, {Key, NewOutPorts}, NewRest} ->
            combine_bridge_points([{Key, lists:usort(OutPorts ++ NewOutPorts)} | NewRest]);
        false ->
            [{Key, lists:usort(OutPorts)}] ++ combine_bridge_points(Rest)
    end.

hub_flow_rule({{SwitchId, InPort}, OutPorts}) when is_binary(InPort) ->
    InPortNo = fc_utils:id_to_port_no(InPort),
    %% First, check if there is already a flow rule with the same
    %% match.
    ExistingFlowRule =
        dby:search(
          fun(Id, _NodeMetadata, [], Acc) when Id =:= SwitchId ->
                  %% Starting point. Go on.
                  {continue, Acc};
             (_, #{<<"type">> := #{value := <<"of_flow_table">>},
                   <<"table_no">> := #{value := 0}},
              [{TheSwitchId, _, #{<<"type">> := #{value := <<"of_resource">>}}}],
              Acc) when TheSwitchId =:= SwitchId ->
                  %% Flow table 0, linked to the switch with an of_resource link.
                  %% Go on and find its flow rules.
                  {continue, Acc};
             (Id, #{<<"type">> := #{value := <<"of_flow_mod">>},
                    <<"matches">> := #{value := Matches},
                    <<"instructions">> := #{value := Instructions}},
              _, Acc) ->
                  %% A flow rule.
                  case Matches of
                      [#{<<"match">> := <<"in_port">>,
                         <<"value">> := TheInPortNo}] when TheInPortNo =:= InPortNo ->
                          %% Match the same inport we care about, and nothing else.
                          %% This is the rule we want.
                          {stop, {Id, Matches, Instructions}};
                      _ ->
                          %% Not the rule we're looking for.
                          {skip, Acc}
                  end;
             (_, _, _, Acc) ->
                  %% Skip everything else.
                  {skip, Acc}
          end,
          not_found,
          SwitchId,
          [depth, {max_depth, 2}]),
    DefaultPriority = 50,
    case ExistingFlowRule of
        not_found ->
            {SwitchId, ?OF_VERSION,
             {[{in_port, InPortNo}],
              [{apply_actions,
                [{output, fc_utils:id_to_port_no(OutPort), no_buffer} || OutPort <- OutPorts]}],
              [{table_id, 0}, {cookie, unique_cookie()}, {priority, DefaultPriority}]}};
        {Cookie, Matches, Instructions} ->
            ExistingOutports =
                case [Instruction ||
                         Instruction = #{<<"instruction">> := <<"apply_actions">>} <- Instructions] of
                    [] ->
                        [];
                    [#{<<"actions">> := Actions}] ->
                        [OutPort || #{<<"action">> := <<"output">>, <<"port">> := OutPort} <- Actions]
                end,
            NewOutPorts = lists:usort(lists:map(fun fc_utils:id_to_port_no/1, OutPorts)
                                      ++ ExistingOutports),
            {SwitchId, ?OF_VERSION,
             {Matches,
              [{apply_actions,
                [{output, OutPort, no_buffer} || OutPort <- NewOutPorts]}],
              %% XXX: should we take priority of existing rule into account?
              [{table_id, 0}, {cookie, Cookie}, {priority, DefaultPriority}]}}
    end.

tap_flow_rules(SourceEndpoint, TargetEndpoint) ->
    Path = case dobby_oflib:get_path(SourceEndpoint, TargetEndpoint) of
               {ok, Graph} ->
                   vertices_edges_path(Graph, SourceEndpoint, TargetEndpoint);
               {error, no_path} ->
                   io:format(standard_error,
                             "No path found between '~s' and '~s'~n",
                             [SourceEndpoint, TargetEndpoint]),
                   error({no_path, SourceEndpoint, TargetEndpoint})
           end,
    io:format("Got path: ~p~n", [Path]),

    TapPoints = tap_points(Path),
    io:format("Got tap points: ~p~n", [TapPoints]),

    lists:append(lists:map(fun tap_flow_rule/1, TapPoints)).

tap_points([{_, endpoint, _}]) ->
    %% Nothing more to do.
    [];
tap_points([{_, endpoint, _}, connected_to | [{_, of_port, _} | _] = Tail]) ->
    tap_points(Tail);
tap_points([{_, of_port, _}, connected_to | [{_, of_port, _} | _] = Tail]) ->
    tap_points(Tail);
tap_points([{_, of_port, _}, connected_to | [{_, endpoint, _} | _] = Tail]) ->
    tap_points(Tail);
tap_points([{Port1, of_port, _}, part_of, {SwitchId, of_switch, _SwitchMetadata},
              part_of | [{Port2, of_port, _} | _] = Tail]) ->
    Tap = {SwitchId, Port1, Port2},
    [Tap] ++ tap_points(Tail).

tap_flow_rule({SwitchId, InPort, OutPort}) when is_binary(InPort) ->
    InPortNo = fc_utils:id_to_port_no(InPort),
    OutPortNo = fc_utils:id_to_port_no(OutPort),
    %% First, check if there is already a flow rule with the same
    %% match.
    ExistingFlowRule =
        dby:search(
          fun(Id, _NodeMetadata, [], Acc) when Id =:= SwitchId ->
                  %% Starting point. Go on.
                  {continue, Acc};
             (_, #{<<"type">> := #{value := <<"of_flow_table">>},
                   <<"table_no">> := #{value := 0}},
              [{TheSwitchId, _, #{<<"type">> := #{value := <<"of_resource">>}}}],
              Acc) when TheSwitchId =:= SwitchId ->
                  %% Flow table 0, linked to the switch with an of_resource link.
                  %% Go on and find its flow rules.
                  {continue, Acc};
             (Id, #{<<"type">> := #{value := <<"of_flow_mod">>},
                    <<"matches">> := #{value := Matches},
                    <<"instructions">> := #{value := Instructions}},
              _, Acc) ->
                  %% A flow rule.
                  case Matches of
                      [#{<<"match">> := <<"in_port">>,
                         <<"value">> := TheInPortNo}] when TheInPortNo =:= InPortNo ->
                          %% Match the same inport we care about, and nothing else.
                          %% Check that it outputs to the right port.
                          case [Instruction ||
                                   Instruction = #{<<"instruction">> := <<"apply_actions">>} <- Instructions] of
                              [] ->
                                  %% No "apply actions" instruction.  Not interesting.
                                  {skip, Acc};
                              [#{<<"actions">> := Actions}] ->
                                  OutPorts = [ThisOutPort ||
                                                 #{<<"action">> := <<"output">>, <<"port">> := ThisOutPort} <- Actions],
                                  case lists:member(OutPortNo, OutPorts) of
                                      true ->
                                          %% Output port matches as
                                          %% well.  This is the rule
                                          %% we want to tap.
                                          {stop, {Id, Matches, Instructions}};
                                      false ->
                                          %% No, the output port doesn't match.
                                          {skip, Acc}
                                  end
                          end;
                      _ ->
                          %% Not the rule we're looking for.
                          {skip, Acc}
                  end;
             (_, _, _, Acc) ->
                  %% Skip everything else.
                  {skip, Acc}
          end,
          not_found,
          SwitchId,
          [depth, {max_depth, 2}]),
    DefaultPriority = 50,
    case ExistingFlowRule of
        not_found ->
            io:format(standard_error,
                      "Expected flow rule in switch ~s from port ~p to port ~p, but none found~n",
                      [SwitchId, InPort, OutPort]),
            [];
        {Cookie, Matches, Instructions} ->
            ExistingOutports =
                case [Instruction ||
                         Instruction = #{<<"instruction">> := <<"apply_actions">>} <- Instructions] of
                    [] ->
                        [];
                    [#{<<"actions">> := Actions}] ->
                        [TheOutPort || #{<<"action">> := <<"output">>, <<"port">> := TheOutPort} <- Actions]
                end,
            NewOutPorts = lists:usort([controller] ++ ExistingOutports),
            DecodedMatches = lists:map(
                               fun(#{<<"match">> := Field, <<"value">> := Value}) ->
                                       {binary_to_atom(Field, utf8), Value}
                               end, Matches),
            [{SwitchId, ?OF_VERSION,
              {DecodedMatches,
               [{apply_actions,
                 [{output, TheOutPort, no_buffer} || TheOutPort <- NewOutPorts]}],
               %% XXX: should we take priority of existing rule into account?
               [{table_id, 0}, {cookie, Cookie}, {priority, DefaultPriority}]}}]
    end.
