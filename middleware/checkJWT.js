const JWT = require("jsonwebtoken");

module.exports = async (req, res, next) => {
  //JWTをもっているか確認->リクエストヘッダの中のx-auth-tokenを確認
  const token = req.header("x-auth-token");
  console.log(token)
  if (!token) {
    //トークンの有無チェック
    console.log("トークンが送られてきませんでした（トークンがありませんでした）");
    res.status(400).json([
      {
        message: "権限がありません。"
      },
    ]);
  } else {
    //トークンの有効期限と署名の検証
    try {
      let user = await JWT.verify(token, "SECRET_KEY")
      console.log("トークンから情報がでコードされ、検証が行われました。");
      req.user = user.email;
      next();
    } catch {
      console.log("トークンが一致しなかったため、リクエストを拒否しました。");
      return res.status(400).json([
        {
          message: "権限がありません。",
        },
      ]);
    }
  }
}