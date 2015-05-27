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

id_to_port_no(OFPortId) ->
    %% XXX: we should keep port numbers in the node metadata
    case re:run(OFPortId, "/OFP([0-9]*)$",[{capture, all_but_first, list}]) of
        {match, [PortNoS]} ->
            list_to_integer(PortNoS);
        nomatch ->
            error(invalid_ofport_id, [OFPortId])
    end.

