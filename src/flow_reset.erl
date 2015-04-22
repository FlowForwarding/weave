-module(flow_reset).

-export([main/0]).

-include_lib("kernel/include/inet.hrl").

clear_flows({DatapathId, Version}) ->
    io:format("CLEARING FLOWS on ~p~n", [DatapathId]),
    Msg = of_msg_lib:flow_delete(Version, [], [{table_id, 0}]),
    {ok, noreply} = ofs_handler:sync_send(DatapathId, Msg),
    ok.

main() ->
    SwitchesS = init:get_plain_arguments(),
    %% If any switches are specified, don't listen for connections.
    application:load(of_driver),
    application:set_env(of_driver, listen, false),

    {ok, _} = application:ensure_all_started(dobby),
    {ok, _} = application:ensure_all_started(flowcompiler),
    %% Wait for Dobby's Mnesia table.
    ok = mnesia:wait_for_tables([identifier], 10000),

    % connect to switches and collect the parsed IP addresses
    SwitchIps = lists:foldl(fun (IpAddr, Acc) ->
                                [connect_to_switch(IpAddr) | Acc]
                            end, [], SwitchesS),
    %% ensure they are connected.
    case lists:foldl(fun wait_for_switch/2, 10, SwitchIps) of
        0 ->
            io:format(standard_error, "Timeout while waiting for switches\n", []),
            halt(1);
        Remaining when is_integer(Remaining) ->
            ok
    end,

    DatapathIds = [{DpId, Version} ||
                        {_, DpId, Version, _} <- simple_ne_logic:switches()],
    lists:foreach(fun clear_flows/1, DatapathIds),
    io:format("~b SWITCHES RESET\n", [length(DatapathIds)]),
    % reset mnesia
    ok = dby_db:clear(),
    io:format("CLEARED DOBBY\n", []),
    halt(0).

% doesn't work if there's more than one switch on the same IP address
wait_for_switch(IpAddr, Remaining) ->
    case lists:keymember(IpAddr, 1, AllSwitches = simple_ne_logic:switches()) of
        true ->
            io:format("Switch ~p is online\n", [IpAddr]),
            Remaining;
        false when Remaining =< 0 ->
            io:format("Timeout waiting for switch ~p\n", [IpAddr]),
            Remaining;
        false ->
            io:format("Switch ~p is offline; waiting... (~p)\n", [IpAddr, AllSwitches]),
            timer:sleep(1000),
            wait_for_switch(IpAddr, Remaining - 1)
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
    SwitchIP.
