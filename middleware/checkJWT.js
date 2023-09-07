const JWT = require("jsonwebtoken");

module.exports = async (req, res, next) => {
  //JWTをもっているか確認->リクエストヘッダの中のx-auth-tokenを確認
  const token = req.header("x-auth-token");

  if (!token) {
    console.log("トークンが送られてきませんでした（トークンがありませんでした）");
    res.status(400).json([
      {
        message: "権限がありません"
      },
    ]);
  } else {

    try {
      let user = await JWT.verify(token, "SECRET_KEY")
      console.log(user)
      req.user = user.email;
      next();
    } catch {
      console.log("トークンが一致しなかったため、リクエストを拒否しました");
      return res.status(400).json([
        {
          message: "トークンが一致しません",
        },
      ]);
    }

  }
}