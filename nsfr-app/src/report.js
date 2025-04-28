const logger = require("./logger");
const { db } = require("./firebase");

async function submitReport(ip, victimNote, location = "Unknown") {
  try {
    const timestamp = new Date().toISOString();
    const report = {
      ip,
      location,
      timestamp,
      comment: victimNote,
      status: "pending"
    };

    const ref = db.ref("fraud_events").push();
    await ref.set(report);
    logger.info(`Victim report submitted: IP=${ip}, Note="${victimNote}": Another fraudster caught by NSFR 2.0!`);
    return ref.key;
  } catch (error) {
    logger.error(`Report submission failed: ${error.message}`);
    throw error;
  }
}

module.exports = { submitReport };