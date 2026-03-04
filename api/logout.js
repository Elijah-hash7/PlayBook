const { clearSessionCookie } = require("./lib/auth");

module.exports = function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    res.status(405).json({ error: "Method not allowed" });
    return;
  }

  clearSessionCookie(res);
  res.status(200).json({ ok: true });
};
