# ネットワークの中継

ブラウザは TCP の接続を張れず、名前も引けません。そのためブラウザのゲストは、中継を
通して [ネットワーク](./features#network) を使います。中継は、ゲストの代わりに
接続して名前を引く、小さな WebSocket のサーバーです。npm のパッケージに 1 つ入って
います（`relay.mjs`。Node.js 用で、依存はありません）。どの言語でも中継を書けるよう、
通信の決まりも下に書きます。

## ページから使う {#use-it-from-a-page}

`network.relay` に中継を指定します。

```js
const guest = launcher.run({
  program: "/bin/git",
  args: ["git", "clone", "https://github.com/aletheia-works/paludarium"],
  network: {
    allow: ["github.com:443"],
    relay: { url: "wss://relay.example/", protocols: ["lambda-microvms", "lambda-microvms.port.8080"] },
  },
});
```

- **`url`** は中継の `ws:` か `wss:` の URL です。HTTPS で配るページには `wss:` が
  要ります。
- **`protocols`** は、WebSocket ごとに申し出るサブプロトコルで、
  `new WebSocket(url, protocols)` と同じ形です。たとえば AWS Lambda MicroVMs は、
  認証のトークンとポートをこれで受け取ります（`lambda-microvms`、
  `lambda-microvms.authentication.<token>`、`lambda-microvms.port.<n>`）。
- **決めるのは今までどおり `network.allow` です。** ゲストが届く先と引ける名前は
  これで決まり、それ以外はカーネルが中継に届く前に断ります。DNS の代わりも、
  同じ決まり（許した名前だけ引き、その名前は global のアドレスにだけ向ける）を
  保ちます。中継も、自分の許可リストで確かめます。

Node.js の外では、`relay` のない `network` は `unimplemented` です。Node.js では
`relay` は省けます。省くとまとめ役が自分で接続して名前を引き、指定するとブラウザと
同じく中継を通します。

## 中継を動かす {#run-the-relay}

```sh
node node_modules/@aletheia-works/paludarium-wasm/relay.mjs \
  --listen 0.0.0.0:8080 --allow github.com:443 --allow '*.github.com:443' \
  --origin https://app.example
```

待ち受けを始めると `{"url":"ws://0.0.0.0:8080/"}` を出力します。WebSocket はどの
パスでも受け、`GET /healthz` には `ok` と答えます。

| オプション | 環境変数 | 意味 |
|---|---|---|
| `--listen ip:port` | `PALUDARIUM_RELAY_LISTEN` | 待ち受ける場所（既定は `127.0.0.1:8080`） |
| `--allow entry`（複数可） | `PALUDARIUM_RELAY_ALLOW` | 中継の許可リスト。`network.allow` と同じ書き方で、必須 |
| `--origin origin`（複数可） | `PALUDARIUM_RELAY_ORIGINS` | 指定すると、受けるページの origin をこれだけにする |
| | `PALUDARIUM_RELAY_SECRET` | [チケット](#names-and-tickets) に署名する鍵。ないときは乱数 |

環境変数には、カンマか空白で区切った一覧を書きます。オプションに足されます。

- **中継は自分の許可リストを持ちます。** ページに埋めたトークンや URL は誰にでも
  見えるので、中継が誰でも使える proxy になってはいけません。中継は、自分のリストが
  許す名前だけを引き、許す先にだけ接続します。またカーネルと同じく、名前からは
  loopback、private、link-local などの global でないアドレスに届かせません
  （`localhost` だけは loopback に届きます）。そういうアドレスに届かせるには、
  アドレスそのもの（`127.0.0.1:8080`）を書きます。
- **origin の確認**はブラウザ向けで、ほかのサイトのページが中継を使うのを防ぎます。
  ほかのクライアントはどんな `Origin` でも送れるので、それを防ぐのは許可リストです。
- **同じ URL の後ろに中継を何台も置く**ときは、`PALUDARIUM_RELAY_SECRET` を
  そろえます。名前を引いたのとは別の台に、接続が届くことがあるからです。

モジュールは `startRelay(settings)` と `createRelay(settings)` も出しています
（`@aletheia-works/paludarium-wasm/relay`）。スクリプトから起動したり、自分の HTTP
サーバーにつないだりできます。

コンテナのイメージには、Node.js とパッケージだけが要ります。

```dockerfile
FROM node:latest
RUN npm install -g @aletheia-works/paludarium-wasm
ENV PALUDARIUM_RELAY_LISTEN=0.0.0.0:8080
EXPOSE 8080
CMD ["sh", "-c", "exec node \"$(npm root -g)/@aletheia-works/paludarium-wasm/relay.mjs\""]
```

## 通信の決まり {#protocol}

版は 1 です。ゲストの接続 1 本ごと、名前を引くこと 1 回ごとに、WebSocket を 1 本
使います。そのためブラウザも中継も、その間で状態を持たず、接続の流れの制御は
その WebSocket のものになります。

- **ハンドシェイク。** クライアントは、受け取ったサブプロトコルを申し出ます。中継は、
  申し出に `paludarium.relay.v1` があればそれを、なければ申し出の最初のもの（ブラウザは、
  申し出のどれも選ばないハンドシェイクを失敗にします）を選び、申し出がなければ
  何も選びません。
- **メッセージ。** テキストのメッセージは JSON のオブジェクトで、バイナリのメッセージは
  接続のバイトです。クライアントの最初のメッセージが要求で、`"v": 1` を付けます。
  ほかの版の要求、形の正しくないメッセージ、その状態で許されないメッセージは、
  1008（JSON として読めないものは 1007）で閉じます。10 秒たっても要求がないときも
  1008 で閉じます。
- **アドレス**は `a.b.c.d:port` か `[ipv6]:port` です。
- **エラー**は Linux の errno の数です。中継が許さない先は `ENETUNREACH`（101）で、
  それ以外は接続そのもののエラーです（たとえば `ECONNREFUSED` は 111）。

### 名前を引く {#resolving-a-name}

```json
{ "v": 1, "op": "resolve", "name": "github.com" }
```

中継は 1 回だけ答えて、1000 で閉じます。

```json
{ "op": "resolved", "addresses": [{ "address": "140.82.112.3", "ticket": "1761700000000.q5…" }] }
```

ない名前、中継のリストにない名前、届かせないアドレスしかない名前では、`addresses`
は空です。それ以外の理由で引けなかったときは `{ "op": "failed", "errno": n }` で、
n はそのエラーです（たいていは `EIO`、5）。

### 名前とチケット {#names-and-tickets}

ゲストが接続するのは名前ではなくアドレスです。そこでチケットで、そのアドレスが
中継の許す名前から来たことを示します。チケットは、期限（エポックからのミリ秒で、
引いてから 15 分後）と、中継の鍵での `1\n<name>\n<address>\n<expiry>` の
HMAC-SHA256（base64url）です。クライアントは、受け取ったアドレスごとにチケットを
覚えておき、そのアドレスへの接続に付けて送ります。

### 接続する {#opening-a-connection}

```json
{ "v": 1, "op": "open", "address": "140.82.112.3:443", "tickets": [{ "name": "github.com", "ticket": "1761700000000.q5…" }] }
```

中継のリストがアドレスそのものを書いているときは、`tickets` を省けます。中継が
接続を許すのは、アドレスの規則がそれを書いているとき、または名前の規則がポートも
含めてチケットの名前を書いていて、チケットが正しく、そのアドレスがその名前の
届いてよいものであるときです。答えは

```json
{ "op": "connected", "local": "10.0.0.5:51234" }
```

で、中継の側の端のアドレス（ゲストの `getsockname`）を返します。許さないときは
`{ "op": "failed", "errno": 101 }` を返して、1000 で閉じます。

接続したあとは次のとおりです。

| メッセージ | 送る側 | 意味 |
|---|---|---|
| バイナリ | 両方 | 接続のバイト。順番どおり |
| `{ "op": "end" }` | クライアント | ゲストが送る側を閉じた（`SHUT_WR`） |
| `{ "op": "end" }` | 中継 | 相手が閉じた。入力の終わり |
| `{ "op": "nodelay", "on": true }` | クライアント | `TCP_NODELAY` |
| `{ "op": "credit", "bytes": n }` | クライアント | ゲストがさらに n バイト受け取った |
| `{ "op": "failed", "errno": n }` | 中継 | 接続が失敗したか、リセットされた |

- **流れの制御。** 中継は、クライアントのクレジットより先には、1 本の接続で
  256 KiB までしか送らず、クレジットが来るまで相手から読むのを止めます。
  クライアントは、ゲストが受け取った分を、その 4 分の 1 ずつクレジットとして返し、
  受け取りが止まっていたときはすぐに返します。クライアントのほうも、WebSocket の
  バッファに 1 MiB たまっている間は送りません。
- **閉じる。** ゲストがソケットを閉じると、クライアントは WebSocket を 1000 で
  閉じます。中継は、クライアントが送った分を送ってから TCP を閉じます。中継は、
  TCP の接続が閉じたら（`end` や `failed` を送ったあとで）1000 で閉じます。
  `end` の前にほかの形で閉じた WebSocket は、ゲストにはリセット（`ECONNRESET`）で、
  `connected` の前に閉じたものは `ENETUNREACH` です。
