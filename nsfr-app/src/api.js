const express = require("express");
const { exportData } = require("./export");
const { submitReport } = require("./report");
const logger = require("./logger");

const router = express.Router();

router.get("/export/:type", async (req, res) => {
  const { type } = req.params;
  const { filter } = req.query;
  if (!["authority_reports", "fraud_events"].includes(type)) {
    logger.warn(`Invalid export type: ${type}`);
    return res.status(400).json({ error: "Invalid type" });
  }

  const filterFn = filter ? (record) => record[filter.split("=")[0]] === filter.split("=")[1] : null;
  try {
    const count = await exportData(type, `${type}.csv`, filterFn);
    res.json({ message: `Exported ${count} records`, file: `${type}.csv` });
  } catch (error) {
    logger.error(`Export API failed for ${type}: ${error.message}`);
    res.status(500).json({ error: "Export failed" });
  }
});

router.post("/report", async (req, res) => {
  const { ip, victimNote, location } = req.body;
  if (!ip || !victimNote) {
    logger.warn("Missing IP or victim note in /report");
    return res.status(400).json({ error: "IP and victim note required" });
  }

  try {
    const key = await submitReport(ip, victimNote, location);
    logger.info(`Report submitted via API: IP=${ip}, Note="${victimNote}"`);
    res.json({ message: "Report submitted", id: key });
  } catch (error) {
    logger.error(`Report submission failed: ${error.message}`);
    res.status(500).json({ error: "Report submission failed" });
  }
});

module.exports = router;