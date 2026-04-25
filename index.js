// Vercel Serverless Function 入口
// 直接复用 Express app（server.js 已在 IS_SERVERLESS 时跳过 listen 与定时任务）
module.exports = require('../server');
