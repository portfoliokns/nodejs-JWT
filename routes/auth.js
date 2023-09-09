const router = require("express").Router();
const { body, validationResult } = require('express-validator');
const {User} = require("../db/User");
const bcrypt = require("bcrypt");
const token_time_out = "120s";
const exit_time = "1s"
const checkJWT = require("../middleware/JWT");

router.get("/", (req, res) => {
  res.send("Hello Auth JS");
});

//ユーザー新規登録用のAPI
router.post(
  "/register",
  body("email").isEmail(),
  body("password").isLength({ min: 6}),
  async (req, res) => {
    const email = req.body.email;
    const password = req.body.password;

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      console.log("バリデーションチェックを通過しませんでした。ユーザーの新規登録はされていません。");
      return res.status(400).json({errors: errors.array()})
    }

    //DBにユーザーが存在しているか確認
    const user = User.find((user) => user.email === email)
    if (user) {
      console.log("すでにユーザーが登録されているため、ユーザーの新規登録は行われていません。");
      return res.status(400).json([
        {
          message: "すでにそのユーザーは存在しています。",
        },
      ]);
    };

    //パスワードの暗号化
    let hashedPassword = await bcrypt.hash(password, 10);

    //DBへの保存（擬似的に保存）
    User.push({
      email,
      password: hashedPassword,
    });
    console.log("DBへ保存が完了し、ユーザーが新たに登録されました。");

    // トークンを生成
    const token = checkJWT.generateToken(email, token_time_out);

    console.log("トークンがクライアント側に渡さされました。");
    return res.json({
      token: token,
    });
  }
);

//DBのユーザーを確認するAPI
router.post("/allUsers", checkJWT.authenticateToken,(req, res) => {
  console.log("登録されているユーザー情報が確認されました。");
  return res.json(User);
});

//ログイン用のAPI
router.post("/login", async (req, res) => {
  const {email, password} = req.body;

  //ユーザー登録状況をチェック
  const user = User.find((user) => user.email === email);
  if (!user) {
    console.log("ユーザーが存在しないため、ログイン拒否しました。");
    return res.status(400).json([
      {
        message: "ユーザー名またはパスワードに誤りがあります。",
      },
    ]);
  };

  //パスワードの複合、照合
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    console.log("パスワードに誤りがあるため、ログイン拒否しました。");
    return res.status(400).json([
      {
        message: "ユーザー名またはパスワードに誤りがあります"
      }
    ])
  }
  console.log("ユーザーがログインに成功しました。");

  ///トークンを生成
  const token = checkJWT.generateToken(email, token_time_out);
  console.log("トークンがクライアント側に渡さされました。");
  return res.json({
    token: token,
  })

});

// ログアウト用のAPI
router.post("/logout", checkJWT.authenticateToken,async (req, res) => {

  //トークンを無効化
  const client_token = req.header("x-auth-token");
  checkJWT.addUnableToken(client_token);
  console.log("トークンを無効化しました。");

  // 新しいトークンを生成
  const token = checkJWT.generateToken(client_token, exit_time);
  console.log("新たなトークンを生成しました。");

  // クライアント側でトークンを更新することを通知
  console.log("ログアウトしました。");
  return res.json({
    token: token,
  });
});

module.exports = router;