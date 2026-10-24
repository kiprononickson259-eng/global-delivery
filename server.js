// Local entry point: run with  npm start
const { app, ready, USE_PG } = require('./app');

ready
  .then(() => {
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () =>
      console.log(`Global Delivery Services running on http://localhost:${PORT} (${USE_PG ? 'online database' : 'local database file'})`));
  })
  .catch(() => process.exit(1));
