-module(flowcompiler).

-export([setup_flow/2,
         main/0]).

-include_lib("kernel/include/inet.hrl").

%% @doc Set up a net flow from `Source' to `Destination'.
%%
%% Determine what flow rules are required to route IP packets from
%% `Source' to `Destination' and back.  Install the flow rules in the
%% switches, and publish them in Dobby.
%%
%% `Source' and `Destination' are binaries that name endpoints present
%% in Dobby.
-spec setup_flow(binary(), binary()) -> _.
setup_flow(Source, Destination)
  when is_binary(Source), is_binary(Destination) ->
    FlowRules = fc_find_path:path_flow_rules(Source, Destination),
    lists:foreach(fun send_flow_rules/1, FlowRules),
    FlowModIds =
        lists:map(
          fun(DatapathFlowMod) ->
                  {ok, FlowModId} =
                      dobby_oflib:publish_dp_flow_mod(<<"flowcompiler">>, DatapathFlowMod),
                  FlowModId
          end, FlowRules),
    dobby_oflib:publish_net_flow(
      <<"flowcompiler">>,
      Source,
      Destination,
      FlowModIds).

lookup_dpids(FlowRules) ->
    lists:map(fun lookup_dpid/1, FlowRules).

lookup_dpid({DobbyId, OFVersion, FlowMod} = FlowRule) ->
    case dby:search(
           fun(Id, #{<<"datapath_id">> := #{value := DpId}}, [], _) when Id =:= DobbyId ->
                   {stop, {ok, DpId}};
              (Id, #{}, [], _) when Id =:= DobbyId ->
                   {stop, {error, missing_datapath_id}}
           end,
           {error, switch_not_in_dobby},
           DobbyId,
           [{max_depth, 1}]) of
        {ok, DpId} ->
            {DpId, OFVersion, FlowMod};
        {error, Error} ->
            error(Error, [FlowRule])
    end.

send_flow_rules({Dpid, OFVersion, {Matches, Instr, Opts}}) when is_binary(Dpid) ->
    Msg = of_msg_lib:flow_add(OFVersion, Matches, Instr, Opts),
    {ok, noreply} = ofs_handler:sync_send(binary_to_list(Dpid), Msg),
    ok.

main() ->
    case parse_arguments(init:get_plain_arguments()) of
        {weave, JSONFileOrNodeName, SourceS, DestinationS, SwitchesS, IsDemo} ->
            weave(JSONFileOrNodeName, SourceS, DestinationS, SwitchesS, IsDemo);
        {tap, NodeName, SourceS, DestinationS, SwitchesS} ->
            tap(NodeName, SourceS, DestinationS, SwitchesS)
    end.

parse_arguments(Arguments) ->
    case Arguments of
        ["-tap", JSONFileOrNodeName, SourceS, DestinationS | SwitchesS] ->
            {tap, JSONFileOrNodeName, SourceS, DestinationS, SwitchesS};
        ["-demo", JSONFileOrNodeName, SourceS, DestinationS | SwitchesS] ->
            IsDemo = true,
            {weave, JSONFileOrNodeName, SourceS, DestinationS, SwitchesS, IsDemo};
        [JSONFileOrNodeName, SourceS, DestinationS | SwitchesS] ->
            IsDemo = false,
            {weave, JSONFileOrNodeName, SourceS, DestinationS, SwitchesS, IsDemo}
    end.

weave(JSONFileOrNodeName, SourceS, DestinationS, SwitchesS, IsDemo) ->
    %% If any switches are specified, don't listen for connections.
    application:load(of_driver),
    SwitchesS =:= [] orelse application:set_env(of_driver, listen, false),

    {ok, _} = application:ensure_all_started(flowcompiler),
    connect_or_load_json(JSONFileOrNodeName),

    Source = list_to_binary(SourceS),
    case fc_find_path:use_bridge_rules(Source) of
        true ->
            HubDestinations = lists:map(fun list_to_binary/1, string:tokens(DestinationS, ",")),
            FlowRules = fc_find_path:hub_flow_rules(Source, HubDestinations);
        false ->
            Destination = list_to_binary(DestinationS),
            %% Ready to find flow rules!
            FlowRules = fc_find_path:path_flow_rules(Source, Destination)
    end,

    io:format("Generated flow rules:\n"),
    lists:foreach(fun print_flow_rule/1, FlowRules),

    DpidFlowRules = lookup_dpids(FlowRules),
    io:format("\n\nFlow rule summary:\n"),
    io:format("~8s ~25s ~3s ~12s ~10s ~4s~n",
              ["Cookie", "Switch datapath id", "In", "Out", "Matches", "Prio"]),
    lists:foreach(fun flow_rule_summary/1, DpidFlowRules),

    case IsDemo of
        false ->
            lists:foreach(fun connect_to_switch/1, SwitchesS),
            %% Now that we know which switches are affected by the flow rules,
            %% ensure that they are connected.
            case lists:foldl(fun wait_for_switch/2, 10, lists:ukeysort(1, DpidFlowRules)) of
                0 ->
                    io:format(standard_error, "Timeout while waiting for switches\n", []),
                    halt(1);
                Remaining when is_integer(Remaining) ->
                    ok
            end,
            lists:foreach(fun send_flow_rules/1, DpidFlowRules);
        true ->
            %% Don't send flow rules to switches, only to Dobby.
            ok
    end,

    %% TODO: publish rules to Dobby, regardless of whether they are
    %% "normal" or "hub" rules.

    FlowModIds =
        lists:map(
          fun(DatapathFlowMod) ->
                  {ok, FlowModId} =
                      dobby_oflib:publish_dp_flow_mod(<<"flowcompiler">>, DatapathFlowMod),
                  FlowModId
          end, FlowRules),
    %% TODO: do something sensible for Destination for hub flow rules
    %% dobby_oflib:publish_net_flow(
    %%   <<"flowcompiler">>,
    %%   Source,
    %%   Destination,
    %%   FlowModIds),
    io:format("~b rules published\n", [length(FlowRules)]),
    %% Attempt to flush Mnesia tables
    mnesia:stop(),
    halt(0).

connect_or_load_json(JSONFileOrNodeName) ->
    %% There are two modes of operation: either connect to an existing
    %% Dobby node, or start it locally and import a JSON file.
    case lists:member($@, JSONFileOrNodeName) of
        true ->
            %% This looks like a node name
            NodeName = list_to_atom(JSONFileOrNodeName),
            connect_to_dobby(NodeName);
        false ->
            %% This looks like a JSON file name.  Let's import it into
            %% a local Dobby instance.
            JSONFile = JSONFileOrNodeName,
            {ok, _} = application:ensure_all_started(dobby),
            %% Wait for Dobby's Mnesia table.
            ok = mnesia:wait_for_tables([identifier], 10000),

            %% Import the JSON file.  Assume that it's in the legacy format
            %% for now.
            case dby_bulk:import(json0, JSONFile) of
                ok -> ok;
                {error, ImportError} ->
                    io:format(standard_error, "Cannot import JSON file ~s: ~p",
                              [JSONFile, ImportError]),
                    halt(1)
            end
    end.

connect_to_dobby(NodeName) ->
    case net_adm:ping(NodeName) of
        pong ->
            %% We're connected.  Let's install our module into
            %% Dobby, so we can search.
            global:sync(),
            {module, _} = dby:install(?MODULE),
            {module, _} = dby:install(fc_find_path),
            {module, _} = dby:install(dobby_oflib),
            {module, _} = dby:install(dofl_identifier);
        pang ->
            io:format(standard_error, "Cannot connect to Dobby node at ~p; exiting~n", [NodeName]),
            halt(1)
    end.

wait_for_switch({Dpid, _, _} = FlowRule, Remaining) ->
    case lists:keymember(binary_to_list(Dpid), 2, AllSwitches = simple_ne_logic:switches()) of
        true ->
            io:format("Switch ~s is online\n", [Dpid]),
            Remaining;
        false when Remaining =< 0 ->
            io:format("Timeout waiting for switch ~s\n", [Dpid]),
            Remaining;
        false ->
            io:format("Switch ~s is offline; waiting... (~p)\n", [Dpid, AllSwitches]),
            timer:sleep(1000),
            wait_for_switch(FlowRule, Remaining - 1)
    end.

connect_to_switch(SwitchS) ->
    case string:tokens(SwitchS, ":") of
        [HostnameOrIP] ->
            SwitchPort = 6653;
        [HostnameOrIP, PortS] ->
            SwitchPort = list_to_integer(PortS)
    end,
    case inet:parse_ipv4strict_address(HostnameOrIP) of
        {ok, SwitchIP} ->
            ok;
        {error, _} ->
            %% If it's not an IP address, it's probably a hostname.
            case inet:gethostbyname(HostnameOrIP) of
                {error, E} ->
                    io:format(standard_error, "Cannot resolve '~s': ~p\n",
                              [HostnameOrIP, E]),
                    SwitchIP = invalid,
                    halt(1);
                {ok, #hostent{h_addr_list = [SwitchIP | _]}} ->
                    io:format("Connecting to ~s on ~s:~b...\n",
                              [HostnameOrIP, inet:ntoa(SwitchIP), SwitchPort])
            end
    end,
    {ok, _} = of_driver:connect(SwitchIP, SwitchPort),
    ok.

print_flow_rule({Id, _, {Matches, Instr, Opts}}) ->
    io:format("~23s: Match: ~lp\n"
              "~23s  Instr: ~lp\n"
              "~23s  Opts:  ~lp\n",
              [Id, Matches,
               "", Instr,
               "", Opts]).

flow_rule_summary({DpId, _, {Matches, Instr, Opts}}) ->
    Cookie = proplists:get_value(cookie, Opts, <<"???">>),
    InPort = proplists:get_value(in_port, Matches, "???"),
    case lists:keyfind(apply_actions, 1, Instr) of
        {apply_actions, Actions} ->
            OutPorts = [OutPort || {output, OutPort, _} <- Actions];
        false ->
            OutPorts = []
    end,
    OutPortsS = string:join(
                  lists:map(
                    fun(controller) ->
                            %% Shorten this one.
                            "ctl";
                       (Integer) when is_integer(Integer) ->
                            integer_to_list(Integer);
                       (Atom) when is_atom(Atom) ->
                            %% Other reserved ports
                            atom_to_list(Atom)
                    end, OutPorts), ","),
    %% 16#ffff is the default priority from of_msg_lib
    Priority = proplists:get_value(priority, Opts, 16#ffff),
    AllMatchTypes =
        [{ipv4_src, "IPv4"},
         {ipv4_dst, "IPv4"},
         {arp_tpa, "ARP"}],
    MatchTypes =
        lists:usort(
          [Type || {Key, Type} <- AllMatchTypes,
                   lists:keymember(Key, 1, Matches)]),
    MatchTypesS = string:join(MatchTypes, ","),
    io:format(
      "~8s ~25s ~3p ~12s ~10s ~4b~n",
      [Cookie, DpId, InPort, OutPortsS, MatchTypesS, Priority]).

tap(JSONFileOrNodeName, SourceS, DestinationS, SwitchesS) ->
    %% If any switches are specified, don't listen for connections.
    application:load(of_driver),
    SwitchesS =:= [] orelse application:set_env(of_driver, listen, false),

    {ok, _} = application:ensure_all_started(flowcompiler),

    connect_or_load_json(JSONFileOrNodeName),

    FlowRules = fc_find_path:tap_flow_rules(
                  list_to_binary(SourceS),
                  list_to_binary(DestinationS)),
    io:format("~p~n", [FlowRules]),

    io:format("Generated flow rules:\n"),
    lists:foreach(fun print_flow_rule/1, FlowRules),

    io:format("\n\nFlow rule summary:\n"),
    io:format("~8s ~25s ~3s ~12s ~10s ~4s~n",
              ["Cookie", "Switch datapath id", "In", "Out", "Matches", "Prio"]),
    lists:foreach(fun flow_rule_summary/1, FlowRules),

    DpidFlowRules = lookup_dpids(FlowRules),
    lists:foreach(fun connect_to_switch/1, SwitchesS),
    %% Now that we know which switches are affected by the flow rules,
    %% ensure that they are connected.
    case lists:foldl(fun wait_for_switch/2, 10, lists:ukeysort(1, DpidFlowRules)) of
        0 ->
            io:format(standard_error, "Timeout while waiting for switches\n", []),
            halt(1);
        Remaining when is_integer(Remaining) ->
            ok
    end,
    lists:foreach(fun send_flow_rules/1, DpidFlowRules),

    %% Attempt to flush Mnesia tables
    mnesia:stop(),
    halt(0).
