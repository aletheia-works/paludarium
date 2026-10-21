# threads native-first 比較

各 native x86-64 Linux CI 実行で oracle を生成する。`threads.c` は libc に依存せず、観測値を little-endian signed 64-bit で出力する。stdout、stderr、終了ステータス、定義されたメモリ観測値を完全一致で比較する。TID 数値は出力せず、clone 戻り値、parent TID、child TID、gettid の一致関係へ正規化する。アドレス、時刻の生値、スケジューラの実行順序は比較しない。既存WAKEケースはwaiter登録まで繰り返す。追加signal/timerケースは親のready flag後に子を50ms（timeoutケース150ms）遅延させる有限guestで、Host待機登録の正確な同期は内部部品テストで別に検証する。

| ケース | 動作 |
| --- | --- |
| 0–5 | 値不一致、未マップ・非整列アドレス、空 WAIT/WAKE bitset、不正 timespec |
| 6–8 | 相対 WAIT、期限切れ絶対 monotonic/realtime BITSET |
| 9–11 | waiter 不在、不正 timespec ポインタ、未対応 realtime WAIT |
| 12–14 | clone TLS、実行前 child TID、個別 exit、clear_child_tid |
| 15–16 | 親の個別 exit 後も子を保持、exit_group でプロセス終了 |
| 17–20 | private wake、bitset 選択、shared bitset wake、有効 tgkill 検索 |
| 21–23 | signal による WAIT 中断、不正 flag 依存関係、不正 parent TID ポインタ |
| 24–26 | 並行 locked increment、100 回 mutex/condvar 相当 handoff、shared wake |
| 27–29 | 親nanosleep中に子が共有timerを設定・短縮・解除 |
| 30–31 | timeoutなしWAIT/WAIT_BITSET、SA_RESTART handler後に子WAKE |
| 32–33 | 同じsignal/wake順でSA_RESTARTなし |
| 34–35 | SA_RESTART handlerでfutex値を変更、WAIT/WAIT_BITSETの再比較 |
| 36–37 | 相対WAIT/絶対monotonic BITSETの500ms期限中150ms時点でSA_RESTART signal |
| 38 | 子timer解除完了→ready→親200ms relative nanosleep |
| 39 | 子1秒timer設定完了→ready→親200ms relative nanosleep→timer解除 |
| 40 | 子1秒set/500ms shorten/disarmを4回反復完了→ready→親200ms relative nanosleep |
| 41 | 子timer解除完了→ready→親monotonic now+200ms absolute clock_nanosleep |
| 42 | 子timer解除完了→ready→親relative200ms timeout付きWAIT |

全43ケース。27/28はsyscall結果・handler回数・経過500ms未満のboolを出力する（2秒/1.5秒遅延を区別）。29は結果・handler回数・150ms以上のbool。36/37は結果・handler回数・経過400ms以上600ms未満のboolを出力し、生時刻は比較しない。timeout付き再開のerrnoはLinux実測で決め、SA_RESTART一般規則から推定しない。30–35の第3値はhandler後のfutex値。親は子のdoneとclear_child_tidを待ち、late WAKEを含む子の終了を回収する。

38–42ではseq-cst ready store/load（release/acquire以上）により、子のtimer syscall完了が親待機入口より前と確定する。新signal handler/送信は追加しない。出力はsyscall結果・handler回数・経過150ms以上600ms未満のboolであり、期待値はnative実測で確定する。生時刻/TIDは比較しない。elapsed起点はclone前、41の絶対deadlineはready確認後のclock取得から200ms。各ケース30秒watchdogを維持し、既存0–37の観測規則を変更しない。

`scripts/threads-native-observe.py --out target/u5-native-first` は全ケースを独立した30秒の process-group watchdog、kill/reap、raw log 付きで実行する。`--emulator target/debug/paludarium` を追加すると native 実行後に emulator と比較する。ケース16は17、他は0で終了する。native の不一致・エラー観測値はデータとして記録し、errno 表から推定しない。

ケース23は不正 CLONE_PARENT_SETTID ポインタに対する Linux の実動作を観測し、成功した clone を1に正規化する。Linux が parent-TID 書き込み失敗を無視した場合に clone が失敗すると仮定しない。

raw guest は後続ユニットの命令・ライブラリ依存を避けて Rust Mutex、Condvar、Rayon が必要とする同期プリミティブを検証する。完全な probe 実行は別途必要である。REQUEUE/CMP_REQUEUE/WAKE_OP の追加対応は実際の使用要件を観測した場合に行う。
