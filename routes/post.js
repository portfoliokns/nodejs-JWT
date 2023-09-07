const router = require("express").Router();
const { publicPosts, privatePosts } = require("../db/Post");
const checkJWT = require("../middleware/checkJWT");

//誰でも見れる記事閲覧用のAPI
router.get("/public", (req, res) => {
  console.log("Publicの記事がレスポンスされました");
  res.json(publicPosts);
});

//JWTを持っている人用のAPI
router.get("/private", checkJWT,(req, res) => {
  console.log("Privateの記事がレスポンスされました");
  res.json(privatePosts);
});

module.exports = router;