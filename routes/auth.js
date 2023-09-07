const router = require("express").Router();
const { body, validationResult } = require('express-validator');
const {User} = require("../db/User");
const bcrypt = require("bcrypt");
const JWT = require("jsonwebtoken");
const token_time_out = "120s";
const exit_time = "1s"
const blacklist = [];

router.get("/", (req, res) => {
  res.send("Hello Auth JS");
});

//ユーザー新規登録用のAPI
router.post(
  "/register",
  //バリデーションチェック
  body("email").isEmail(),
  body("password").isLength({ min: 6}),
  async (req, res) => {
    const email = req.body.email;
    const password = req.body.password;

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      console.log("バリデーションチェックで問題が発生しました");
      return res.status(400).json({errors: errors.array()})
    }

    //DBにユーザーが存在しているか確認
    const user = User.find((user) => user.email === email)
    if (user) {
      console.log("すでにユーザーが登録されています");
      return res.status(400).json([
        {
          message: "すでにそのユーザーは存在しています。",
        },
      ]);
    };

    //パスワードの暗号化
    let hashedPassword = await bcrypt.hash(password, 10);

    //DBへの保村（擬似的に保存）
    User.push({
      email,
      password: hashedPassword,
    })

    // トークンを生成
    const token = generateToken(email, token_time_out);

    console.log("トークンがクライアントに渡さされました");
    return res.json({
      token: token,
    })
  }
);

//DBのユーザーを確認するAPI
router.get("/allUsers", (req, res) => {
  console.log("登録されているユーザー情報が確認されました");
  return res.json(User);
});

//ログイン用のAPI
router.post("/login", async (req, res) => {
  const {email, password} = req.body;

  const user = User.find((user) => user.email === email);
  if (!user) {
    console.log("ユーザーが存在しないため、ログイン拒否しました");
    return res.status(400).json([
      {
        message: "ユーザー名またはパスワードに誤りがあります",
      },
    ]);
  };

  //パスワードの複合、照合
  const isMatch = await bcrypt.compare(password, user.password);

  if (!isMatch) {
    console.log("パスワードに誤りがあるため、ログイン拒否しました");
    return res.status(400).json([
      {
        message: "ユーザー名またはパスワードに誤りがあります"
      }
    ])
  }

  ///トークンを生成
  const token = generateToken(email, token_time_out);

  console.log("トークンが返却されました");
  return res.json({
    token: token,
  })

});

// ログアウト用のAPI
router.post("/logout", async (req, res) => {
  const { delete_token } = req.body;

  // トークンの付与チェック
  if (!delete_token) {
    console.error("トークンが付与されていません");
    return res.status(400).json({
      message: "トークンが付与されていません",
    });
  };

  // ブラックリストトークンの有無チェック
  if (blacklist.includes(delete_token)) {
    console.error("トークンは既に無効化されています");
    return res.status(401).json({
      message: "トークンは既に無効化されています",
    });
  };

  // トークンをブラックリストに追加
  blacklist.push(delete_token);

  // トークンを生成
  const token = generateToken(delete_token, exit_time);
  console.log(token)

  // クライアント側でトークンを更新することを通知
  console.log("ログアウトしました");
  return res.json({
    token: token,
  });
});

// トークンを生成する共通の関数
function generateToken(para, time) {
  console.log(para, time)
  try {
    const token = JWT.sign(
      { email: para },
      "SECRET_KEY", // 本来は、envなどで秘密鍵を設定
      { expiresIn: time }
    );
    return token;
  } catch (error) {
    console.error("トークン生成エラー:", error);
    throw error;
  }
}

module.exports = router;