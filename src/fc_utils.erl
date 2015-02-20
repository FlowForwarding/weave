-module(fc_utils).

-export([no_to_dpid/1, dpid_to_no/1, ip/1, id/2, id_to_port_no/1]).

id(N, endpoint) ->
    list_to_binary("EP" ++ integer_to_list(N));
id({Sw, N}, of_port) ->
    list_to_binary("OFS"++ integer_to_list(Sw) ++ "/OFP" ++ integer_to_list(N));
id(N, of_switch) ->
    list_to_binary("OFS" ++ integer_to_list(N)).

no_to_dpid(N) ->
    "00:00:00:00:00:01:00:0" ++ integer_to_list(N).

dpid_to_no(Dpid) ->
    [No | _ ] = lists:reverse(Dpid),
    binary_to_integer(<<No>>).

ip(N) ->
    {10, 0, 0, N}.

id_to_port_no(<<"OFS", Tail1/binary>>) ->
    Tail2 = drop_number(Tail1),
    <<"/OFP", PortNoB/binary>> = Tail2,
    binary_to_integer(PortNoB).

drop_number(<<C, Tail/binary>>) when $0 =< C, C =< $9 ->
    drop_number(Tail);
drop_number(Bin) when is_binary(Bin) ->
    Bin.

