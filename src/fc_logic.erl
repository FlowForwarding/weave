-module(fc_logic).

-export([start/0,
         get_switches/0,
         send_flows/2]).

start() ->
    {ok, _Started} = application:ensure_all_started(simple_ne),
    ok.

get_switches() ->
    lists:foldl(fun({IP, Ddpid, _Version, _Pid}, Acc) ->
                        [{Ddpid, IP} | Acc]
                end, [], simple_ne_logic:switches()).

send_flows(Dpid, Flows) ->
    [begin
         Msg = of_msg_lib:flow_add(_Ver = 4, Matches, Instr, Opts),
         ofs_handler:sync_send(Dpid, Msg)
     end || {Matches, Instr, Opts} <- Flows].
