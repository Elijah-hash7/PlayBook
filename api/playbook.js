const fs = require("fs");
const path = require("path");
const { hasValidSession } = require("./lib/auth");

const playbookPath = path.join(__dirname, "templates", "playbook.html");

module.exports = function handler(req, res) {
  if (!hasValidSession(req)) {
    res.statusCode = 302;
    res.setHeader("Location", "/");
    res.end();
    return;
  }

  const html = fs.readFileSync(playbookPath, "utf8");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.status(200).send(html);
};
