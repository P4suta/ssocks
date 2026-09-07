%% SPDX-FileCopyrightText: 2026 ssocks contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

-module(ssocks_clock_ffi).
-export([now_ms/0]).

%% Monotonic rather than wall clock: a deadline computed from a clock that can
%% jump backwards is a deadline that can be missed by an arbitrary amount.
now_ms() -> erlang:monotonic_time(millisecond).
