#!/usr/bin/env escript
%%! +S 1:1 +A 1
-mode(compile).

main(_) ->
    logger:set_primary_config(level, none),
    io:setopts(standard_io, [binary, {encoding, latin1}]),
    frame(),
    case __MODE__ of
        silent -> timer:sleep(2000), halt(0);
        malformed -> send_frame(<<"{}">>), loop(2);
        oversized -> io:put_chars(standard_io, <<4097:32>>), loop(2);
        confirm_crash ->
            send_frame(base64:decode(<<"__HANDSHAKE__">>)), auth_loop(2, confirm_crash);
        confirm_late ->
            send_frame(base64:decode(<<"__HANDSHAKE__">>)), auth_loop(2, confirm_late);
        _ -> send_frame(base64:decode(<<"__HANDSHAKE__">>)), loop(2)
    end.

frame() ->
    case file:read(standard_io, 4) of
        eof -> halt(0);
        {ok, <<N:32>>} ->
            case file:read(standard_io, N) of
                {ok, Data} -> Data;
                _ -> halt(2)
            end;
        _ -> halt(2)
    end.

send_frame(Data) ->
    try ok = file:write(standard_io, <<(byte_size(Data)):32, Data/binary>>)
    catch _:_ -> halt(0)
    end.

loop(Id) ->
    frame(),
    case __MODE__ of
        slow -> timer:sleep(2000);
        crash -> halt(9);
        _ -> ok
    end,
    Data = iolist_to_binary(["{\"version\":1,\"id\":", integer_to_list(Id),
                             ",\"result\":{\"operation\":\"ping\"}}"]),
    send_frame(Data),
    loop(Id + 1).

%% Simulated commit acknowledgement loss: one marker per received confirm.
%% Only the transport contract is under test here; real atomic consumption
%% is exercised by the Rust/DynamoDB pipe integration test.
auth_loop(Id, Mode) ->
    Request = frame(),
    Result = case binary:match(Request, <<"\"operation\":\"init\"">>) of
        nomatch ->
            case binary:match(Request, <<"\"operation\":\"confirm\"">>) of
                nomatch -> <<"{\"operation\":\"ping\"}">>;
                _ ->
                    Marker = filename:join(filename:dirname(escript:script_name()), "confirms"),
                    ok = file:write_file(Marker, <<"1">>, [append]),
                    case Mode of
                        confirm_crash -> halt(9);
                        confirm_late -> timer:sleep(900)
                    end,
                    <<"{\"operation\":\"confirm\",\"session_cookie\":\"fixture-cookie\",",
                      "\"user_id\":\"usr-000102030405060708090a0b0c0d0e0f\",",
                      "\"user_created\":false,\"country\":null}">>
            end;
        _ -> <<"{\"operation\":\"init\"}">>
    end,
    send_frame(iolist_to_binary(["{\"version\":1,\"id\":", integer_to_list(Id),
                               ",\"result\":", Result, "}"])),
    auth_loop(Id + 1, Mode).
