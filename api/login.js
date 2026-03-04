const {
  getPassword,
  getSessionSecret,
  issueSessionCookie,
  safeEqual
} = require("./lib/auth");

module.exports = function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    res.status(405).json({ error: "Method not allowed" });
    return;
  }

  const envPassword = getPassword();
  const sessionSecret = getSessionSecret();
  if (!envPassword || !sessionSecret) {
    res.status(500).json({ error: "Server auth is not configured" });
    return;
  }

  const finish = (inputPassword) => {
    if (!safeEqual(inputPassword, envPassword)) {
      res.status(401).json({ error: "Unauthorized" });
      return;
    }

    res.setHeader("Cache-Control", "no-store");
    issueSessionCookie(res);
    res.status(200).json({ ok: true });
  };

  if (typeof req.body?.password === "string") {
    finish(req.body.password);
    return;
  }

  let raw = "";
  req.on("data", (chunk) => {
    raw += chunk;
  });

  req.on("end", () => {
    let parsed = {};
    try {
      parsed = JSON.parse(raw || "{}");
    } catch {
      parsed = {};
    }
    const inputPassword = typeof parsed.password === "string" ? parsed.password : "";
    finish(inputPassword);
  });
};
