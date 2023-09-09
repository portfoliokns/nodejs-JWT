const JWT = require("jsonwebtoken");
const {UnableToken} = require("../db/UnableToken");

//トークンの有効期限の検証、署名の検証、不正トークンの検証
async function authenticateToken(req, res, next) {
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
    try {
      //トークンの有効期限と署名の検証
      let user = await JWT.verify(token, "SECRET_KEY")
      console.log("トークンから情報がデコードされ、検証が行われました。");

      //無効化トークンの検証
      const isTokenValid = UnableToken.find((tokenItem) => tokenItem.number === token)
      if (isTokenValid) {
        console.log("トークンが無効化されています。操作を拒否しました。");
        return res.status(401).json([
          {
            message: "権限がありません。",
          },
        ]);
      };

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
};

//無効トークンの追加
function addUnableToken(token) {
  UnableToken.push({
    number: token,
  });
};

module.exports = {
  authenticateToken,
  addUnableToken,
};