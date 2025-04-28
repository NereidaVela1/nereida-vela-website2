const admin = require("firebase-admin");
const logger = require("./logger");

try {
  const serviceAccount = require("../serviceAccountKey.json");

  if (!admin.apps.length) {
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
      databaseURL: "https://nsfr-fraud-tracker-default-rtdb.firebaseio.com/"
    });
  }

  const db = admin.database();
  const storage = admin.storage();

  module.exports = {
    db,
    storage,
    admin,
    cleanup: () => {
      return Promise.all(admin.apps.map(app => app.delete()))
        .then(() => logger.info("Firebase app closed"))
        .catch(err => logger.error(`Failed to close Firebase: ${err.message}`));
    }
  };
} catch (error) {
  logger.error(`Firebase initialization failed: ${error.message}`);
  throw error;
}