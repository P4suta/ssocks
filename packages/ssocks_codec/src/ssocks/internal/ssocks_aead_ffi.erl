%% SPDX-FileCopyrightText: 2026 ssocks contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

%% Erlang side of the AEAD funnel.
%%
%% Two things are deliberate here. The cipher name that crosses the boundary is
%% the crypto library spelling, never the Shadowsocks protocol spelling, so the
%% translation lives on the Gleam side where it is type checked. And `open`
%% catches everything, because its ciphertext and tag come off the network:
%% crypto:crypto_one_time_aead/7 returns the atom `error` for a failed tag but
%% raises badarg for a malformed one, and both must read as "did not
%% authenticate" rather than crashing the connection process.

-module(ssocks_aead_ffi).

-export([available/2, seal/5, open/6]).

cipher(<<"aes-128-gcm">>) -> aes_128_gcm;
cipher(<<"aes-256-gcm">>) -> aes_256_gcm;
cipher(<<"chacha20-poly1305">>) -> chacha20_poly1305.

available(Name, _KeySize) ->
    try
        lists:member(cipher(Name), crypto:supports(ciphers))
    catch
        _:_ -> false
    end.

seal(Name, Key, Nonce, Aad, Plaintext) ->
    crypto:crypto_one_time_aead(cipher(Name), Key, Nonce, Plaintext, Aad, true).

open(Name, Key, Nonce, Aad, Ciphertext, Tag) ->
    try crypto:crypto_one_time_aead(cipher(Name), Key, Nonce, Ciphertext, Aad, Tag, false) of
        error -> {error, nil};
        Plaintext when is_binary(Plaintext) -> {ok, Plaintext}
    catch
        _:_ -> {error, nil}
    end.
