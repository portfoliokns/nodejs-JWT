# このリポジトリについて
【勉強用】これはJWTを用いて、WebAPIのアプリを構築した勉強用のリポジトリです

<br>

# 参考ページ
このファイルは以下の動画の教材をもとに作成しています。
https://www.youtube.com/watch?v=IaCQqCIqZ6U

<br>

# 起動方法
ターミナル上で、以下のようにサーバーを起動する
```:例
nodemon
```
Postmanからリクエストを送信して、動作を確認することができます。

# 仕様
- DBは構築しておらず、ハードコーディングしており、擬似的にDB賭して使えるようにしています。（サーバーを停止すると、情報が消えてしまう）
- Postmanからリクエストを送信し、動作を確認することを前提としています。
- パスワードのハッシュ化は、bcryptを用いている
- トークンを発行するために、JWTを用いている
- トークンの有効期限は15分としている

# 学んだこと
- Postmanは、WebAPIの動作を確認するために、擬似的にリクエストを送ることのできるツール
- ハッシュ化には、bcryptというnpmを用いていること
- トークンを発行したり、トークンの有効期間を制御するためにJWTを用いていること
- JWTでトークンを利用する場合、JWTは主に有効期限と署名の検証・結果が保証される
- そのため認証や認可については、開発者側で制御する必要がある（ペイロードからデコードすると、E-mail情報を復号できる）
- E-mailやパスワードといった情報はbodyの中に埋め込んでリクエストする（SAML認証やトークンベースの場合、リクエストする形式が異なる）
- トークンをリクエストする場合は、HTTPヘッダの中に埋め込んでPOSTリクエストする
- ログアウトした後などで、トークンを無効化したい場合は、トークン情報を保存しておき、そのトークンからのリクエストを拒否する必要がある。（攻撃を防御するために必要な機能）このコードではログアウト時に、クライアント側から受け取ったトークンを無効トークンとして追加する処理を実装している。万が一、無効トークンと同じトークンが再び送られても、無効化されていることを判断する処理が走るため、権限がないというリクエストが返ってくる。