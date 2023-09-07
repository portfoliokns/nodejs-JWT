const router = require("express").Router();
const { body, validationResult } = require('express-validator');
const {User} = require("../db/User");
const bcrypt = require("bcrypt");
const JWT = require("jsonwebtoken");
const timeout = "120s";

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
    
    //JWTの発行（クライアントへの発行）
    const token = await JWT.sign({
      email,
    },
    "SECRET_KEY", //本来は、envなどで第三者に見られないようにする必要がある。
    {
      expiresIn: timeout,
    }
    );

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

  const token = await JWT.sign(
    {
      email,
    },
    "SECRET_KEY", //本来は、envなどで第三者に見られないようにする必要がある。
    {
      expiresIn: timeout,
    }
  );

  console.log("トークンが返却されました");
  return res.json({
    token: token,
  })

});

module.exports = router;