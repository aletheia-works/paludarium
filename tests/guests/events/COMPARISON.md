# U6 有限比較ケース

## Catalog

raw Linux ABI guestは0〜81の82件、Rust target guest timer/unixの2件、計84件を固定する。元69件のgreen source aeb7d59c8c611bc3120380ea60707e0369dfa683と品質証拠は歴史として保持する。追加67〜81はET未読追加writeとpwait一時mask境界のnative先行観測待ちであり、製品修正前にfixture-only CIで期待を取得する。保存期待fixtureは作らない。

| ID | ケース | 比較 |
| --- | --- | --- |
| 0 | event_initial | raw4個の64bit観測値 |
| 1 | event_add | raw4個の64bit観測値 |
| 2 | event_semaphore | raw4個の64bit観測値 |
| 3 | event_empty | raw4個の64bit観測値 |
| 4 | event_zero_write | raw4個の64bit観測値 |
| 5 | event_max_write | raw4個の64bit観測値 |
| 6 | event_overflow | raw4個の64bit観測値 |
| 7 | event_short_read | raw4個の64bit観測値 |
| 8 | event_short_write | raw4個の64bit観測値 |
| 9 | event_fault_read | raw4個の64bit観測値 |
| 10 | event_fault_write | raw4個の64bit観測値 |
| 11 | event_invalid_flags | raw4個の64bit観測値 |
| 12 | event_dup_lifetime | raw4個の64bit観測値 |
| 13 | event_shared_flags | raw4個の64bit観測値 |
| 14 | event_cloexec | raw4個の64bit観測値 |
| 15 | event_poll | raw4個の64bit観測値 |
| 16 | epoll_invalid_flags | raw4個の64bit観測値 |
| 17 | epoll_legacy_size | raw4個の64bit観測値 |
| 18 | epoll_data | raw4個の64bit観測値 |
| 19 | epoll_lt | raw4個の64bit観測値 |
| 20 | epoll_et | raw4個の64bit観測値 |
| 21 | epoll_oneshot | raw4個の64bit観測値 |
| 22 | epoll_duplicate_add | raw4個の64bit観測値 |
| 23 | epoll_missing_mod | raw4個の64bit観測値 |
| 24 | epoll_missing_del | raw4個の64bit観測値 |
| 25 | epoll_del_null | raw4個の64bit観測値 |
| 26 | epoll_self | raw4個の64bit観測値 |
| 27 | epoll_bad_fd | raw4個の64bit観測値 |
| 28 | epoll_maxevents | raw4個の64bit観測値 |
| 29 | epoll_not_epoll | raw4個の64bit観測値 |
| 30 | epoll_fault_out | raw4個の64bit観測値 |
| 31 | epoll_dup_close | raw4個の64bit観測値 |
| 32 | epoll_duplicate_ofd | raw4個の64bit観測値 |
| 33 | epoll_fd_reuse | raw4個の64bit観測値 |
| 34 | epoll_fairness | raw4個の64bit観測値 |
| 35 | epoll_timeout | raw4個の64bit観測値 |
| 36 | socket_transfer | raw4個の64bit観測値 |
| 37 | socket_bidirectional | raw4個の64bit観測値 |
| 38 | socket_empty | raw4個の64bit観測値 |
| 39 | socket_partial | raw4個の64bit観測値 |
| 40 | socket_eof | raw4個の64bit観測値 |
| 41 | socket_epipe | raw4個の64bit観測値 |
| 42 | socket_shutdown | raw4個の64bit観測値 |
| 43 | socket_flags | raw4個の64bit観測値 |
| 44 | socket_send_recv | raw4個の64bit観測値 |
| 45 | socket_hangup | raw4個の64bit観測値 |
| 46 | socket_et | raw4個の64bit観測値 |
| 47 | socket_bad_pointer | raw4個の64bit観測値 |
| 48 | epoll_signal | raw4個の64bit観測値 |
| 49 | epoll_masked_signal | raw4個の64bit観測値 |
| 50 | epoll_ignored_signal | raw4個の64bit観測値 |
| 51 | epoll_pwait | raw4個の64bit観測値 |
| 52 | network_inet | 承認済みnetwork policy例外 |
| 53 | network_inet6 | 承認済みnetwork policy例外 |
| 54 | socketpair_wrong_domain | 承認済みnetwork policy例外 |
| 55 | socketpair_bad_output | raw4個の64bit観測値 |
| 56 | socketpair_bad_flags | raw4個の64bit観測値 |
| 57 | epoll_invalid_op | raw4個の64bit観測値 |
| 58 | epoll_mod_ready | raw4個の64bit観測値 |
| 59 | event_blocking_signal | raw4個の64bit観測値 |
| 60 | group_kill | SIGKILL exit mapping |
| 61 | timer_metadata_before_epoll | raw4個の64bit観測値 |
| 62 | epoll_nested | raw4個の64bit観測値 |
| 63 | socket_nosignal | raw4個の64bit観測値 |
| 64 | socket_backpressure_readiness | fill末尾errno、初回OUT、飽和時OUT消失、peer全drain後OUT再通知 |
| 65 | socket_short_write_saturation | fill末尾errno、途中short write有無、queued正値、有限fill内飽和 |
| 66 | socket_blocking_write_peer_drains | fill末尾errno、blocking32KiB完了、child peer read進捗、writer NONBLOCK解除 |
| 67 | event_et_unread_write | 最初/未読追加write後の通知、counter合計 |
| 68 | event_et_drain_rewrite | 最初/追加write通知、drain後空、rewrite通知 |
| 69 | event_et_oneshot_unread | 初回通知、disabled時追加write、MOD rearm通知、再disabled |
| 70 | socket_et_unread_write | socketpair結果、最初/未読追加write通知、read3bytes |
| 71 | socket_et_drain_rewrite | 最初/追加write通知、drain後空、rewrite通知 |
| 72 | socket_et_oneshot_unread | 初回通知、disabled時追加write、MOD rearm通知、再disabled |
| 73 | pwait_temporary_unblock_handler | 元SIGALRM blocked→一時unblock、errno、handler回数、return後元mask |
| 74 | pwait_normal_signal | 元unblockedの通常signal、errno、handler回数、return後mask |
| 75 | pwait_masked_signal | 元/一時maskともblocked、有限timeout、handlerなし、元mask |
| 76 | pwait_ignored_signal | 元blocked→一時unblock+SIG_IGN、有限timeout、元mask |
| 77 | pwait_ready_restores_mask | ready即時return、handlerなし、元blocked mask復帰 |
| 78 | pwait_invalid_restores_mask | invalid maxeventsのerrno、handlerなし、元blocked mask復帰 |
| 79 | event_et_output_read | まだwritableなsemaphore read後OUT再通知、反復通知なし |
| 80 | socket_et_output_partial_drain | OUT初回、write後、partial-read、write全量drain後 |
| 81 | socket_et_output_write_boundaries | 複数write後、第一write全量read、第二write部分/全量readのOUT |
| timer | tokio1.48.0 multi-thread runtimeの2timer完了 | stdout/stderr/exit/timeout |
| unix | std UnixStream::pair双方向write/read | stdout/stderr/exit/timeout |

## Rules

通常rawケースはlittle-endian64bit×4のstdoutをそのまま比較する。戻り値、counter、関係bool、固定data tokenと必要なreadiness bitsだけを出力し、生fd/TID/時刻/アドレスを出力しない。case32の複数ready dataは和、case34は2回の選択が異なるboolを使い順不同event順序を要求しない。case35だけ20ms期限を15ms以上1秒未満の区間boolで記録する。signal/timerはkernel setitimerとmask/ignoreの実測、handler回数を記録する。case60はnative signal exit -9を製品CLI128+9へ正規化するがraw exitは保持する。

52/53/54はAF_INET/AF_INET6socket/socketpair禁止方針の専用ケース。native成功/errnoを原本へ保存し、emulatorは承認済みEAFNOSUPPORT(-97)とzero remainderをassertする。nativeとの一致ケースと分けpolicy_exceptionをmanifestへ記録する。未知flags/対応外型も観測前のerrno推定で固定しない。

全process30秒watchdog/kill/reap、raw stdout/stderr/exit/timeoutとbinaryshaを保存。通常native exit0/stderr空、case60native-9/stderr空を検査する。Rustguestのassert失敗はguest成功と扱わない。CI straceはRust targetの実使用syscallを別原本として保存し、timerfd必要性を実測で決める。

## Boundaries

初回64 Cケース成功後のRust adapter、getrandomとmusl clone flagの接続を経て、Tokio timer/UnixStreamと追加backpressure3件を含むLinux69件が成功した。backpressure製品動作は追加64〜66のnative先行取得と親goの後に実装した。fillは64KiB単位1024回、drainは2048回で有限。OSのsend-buffer設定に依存するqueue容量やshort writeの具体バイト数は比較せず、飽和errno、部分成功、OUTの遷移、drainによる進捗という関係を比較する。これはゲストへの資源上限追加ではなくfixture自身の有限境界である。

case66はclone共有Threadがrelease atomicを受けてpeerをdrainし、親のblocking writeを進め、clear-child-TID futexで終了を回収する。releaseはsyscall開始前なので実Host waitへの到達をこのguestだけで保証しない。実待機開始後の解除は内部Host同期テストで別に確かめた。Node/実Safariでは非threaded0〜65とunixを含め、timerと66のguest threadingはU11境界として明示する。登録/通知競合とtimer metadataの内部同期テストは製品実装後の単体テストで検証した。現moduleのNode/実Safari結果は最終原本取得まで未検証。

新しいobservable syscall動作が必要になれば追加guestをnative先行で取得し、この固定84ケースを削らず追加する。Wasmは0〜81のうち66を除く81 Cケース+unix=82件、既存21との合計103件を予定し、全新結果は未検証。DGRAM/SEQPACKETとネットワーク通信は承認済み対応範囲と区別する。U10 probe全量、U11 guest Worker達成を有限結果から推測しない。
