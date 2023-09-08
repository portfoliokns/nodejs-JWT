const JWT = require("jsonwebtoken");

module.exports = async (req, res, next) => {
  //JWTをもっているか確認->リクエストヘッダの中のx-auth-tokenを確認
  const token = req.header("x-auth-token");

  //トークンの有無チェック
  if (!token) {
    console.log("トークンが送られてきませんでした（トークンがありませんでした）");
    res.status(400).json([
      {
        message: "閲覧権限がありません。"
      },
    ]);
  } else {
    try {
      let user = await JWT.verify(token, "SECRET_KEY")
      console.log("トークンから情報がでコードされ、検証が行われました。");
      req.user = user.email;
      next();
    } catch {
      console.log("トークンが一致しなかったため、リクエストを拒否しました。");
      return res.status(400).json([
        {
          message: "閲覧権限がありません。",
        },
      ]);
    }

  }
}