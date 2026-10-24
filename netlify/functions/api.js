// Netlify Function: runs the whole Express app (all /api/... routes)
const serverless = require('serverless-http');
const { app, ready } = require('../../app');

const handler = serverless(app);

exports.handler = async (event, context) => {
  await ready; // database tables and first admin are prepared before the first request
  return handler(event, context);
};
