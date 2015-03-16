-module(flowcompiler).

-export([setup_flow/2]).

setup_flow(Source, Destination)
  when is_binary(Source), is_binary(Destination) ->
    FlowRules = fc_find_path:path_flow_rules(Source, Destination),
    lists:foreach(fun send_flow_rules/1, FlowRules),
    dobby_oflib:publish_new_flow(
      <<"flowcompiler">>,
      Source,
      Destination,
      FlowRules).

send_flow_rules({Dpid, {OFVersion, Flows}}) when is_binary(Dpid) ->
    lists:map(
      fun({Matches, Instr, Opts}) ->
              Msg = of_msg_lib:flow_add(OFVersion, Matches, Instr, Opts),
              {ok, noreply} = ofs_handler:sync_send(binary_to_list(Dpid), Msg)
      end, Flows).
