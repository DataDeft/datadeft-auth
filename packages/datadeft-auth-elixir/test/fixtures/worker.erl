#!/usr/bin/env escript
%%! +S 1:1 +A 1
-mode(compile).

main(_) ->
    logger:set_primary_config(level, none),
    io:setopts(standard_io, [binary]),
    frame(),
    case __MODE__ of
        silent -> timer:sleep(2000), halt(0);
        malformed -> send_frame(<<"{}">>), loop(2);
        oversized -> io:put_chars(standard_io, <<4097:32>>), loop(2);
        _ -> send_frame(base64:decode(<<"__HANDSHAKE__">>)), loop(2)
    end.

frame() ->
    case io:get_chars(standard_io, "", 4) of
        eof -> halt(0);
        <<N:32>> -> io:get_chars(standard_io, "", N);
        _ -> halt(2)
    end.

send_frame(Data) ->
    try io:put_chars(standard_io, <<(byte_size(Data)):32, Data/binary>>)
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
