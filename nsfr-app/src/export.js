const fs = require("fs");
const path = require("path");
const logger = require("./logger");
const { db, cleanup } = require("./firebase");

// Sanitize CSV fields to prevent injection
function sanitizeCsvField(field) {
  if (typeof field !== "string") return field || "";
  if (field.includes(",") || field.includes("\n") || field.includes('"')) {
    return `"${field.replace(/"/g, '""')}"`;
  }
  return field;
}

async function exportData(refPath = "authority_reports", outputFile = "nsfr_authority_report.csv", filter = null) {
  let retryCount = 0;
  const maxRetries = 3;
  const retryDelay = 2000;
  const batchSize = 1000; // Process 1000 records at a time

  while (retryCount < maxRetries) {
    try {
      const ref = db.ref(refPath);
      const snapshot = await ref.orderByKey().limitToFirst(batchSize).once("value");
      const data = snapshot.val();

      if (!data) {
        logger.warn(`No data found in ${refPath} to export`);
        return 0;
      }

      let records = Object.values(data)
        .filter(record => (filter ? filter(record) : true))
        .map(record => ({
          ip: sanitizeCsvField(record.ip || "Unknown"),
          location: sanitizeCsvField(record.location || "Unknown"),
          timestamp: sanitizeCsvField(record.timestamp || new Date().toISOString()),
          comment: sanitizeCsvField(record.comment || ""),
          ...(refPath === "fraud_events" && {
            risk_level: sanitizeCsvField(record.risk_level || "Unknown"),
            xss: record.xss || 0,
            sms: record.sms || 0,
            email: record.email || 0,
            wechat: record.wechat || 0,
            upi: record.upi || 0,
            victim_note: sanitizeCsvField(record.victim_note || "")
          })
        }));

      const headers = refPath === "authority_reports"
        ? ["IP", "Location", "Timestamp", "Comment"]
        : ["IP", "Location", "Timestamp", "Comment", "Risk Level", "XSS", "SMS", "Email", "WeChat", "UPI", "Victim Note"];
      const csvContent = [
        headers.join(","),
        ...records.map(row => headers.map(h => row[h.toLowerCase().replace(" ", "_")] || "").join(","))
      ].join("\n");

      const fullPath = path.resolve(outputFile);
      fs.writeFileSync(fullPath, csvContent, { encoding: "utf-8" });
      logger.info(`Exported ${records.length} records from ${refPath} to ${fullPath}: Fraudsters documented, Nereida’s wrath recorded!`);

      // Log memory usage
      const memoryUsage = process.memoryUsage();
      logger.info(`Memory usage: RSS=${(memoryUsage.rss / 1024 / 1024).toFixed(2)}MB, HeapTotal=${(memoryUsage.heapTotal / 1024 / 1024).toFixed(2)}MB`);

      return records.length;
    } catch (error) {
      retryCount++;
      logger.error(`Export attempt ${retryCount}/${maxRetries} failed for ${refPath}: ${error.message}`);
      if (retryCount < maxRetries) {
        logger.info(`Retrying in ${retryDelay}ms...`);
        await new Promise(resolve => setTimeout(resolve, retryDelay));
      } else {
        logger.error(`Export failed after ${maxRetries} retries: ${error.message}`);
        throw error;
      }
    } finally {
      await cleanup().catch(err => logger.error(`Failed to close Firebase: ${err.message}`));
    }
  }
}

// CLI wrapper for direct execution
async function exportToCsv(outputFile = "nsfr_authority_report.csv", filterStr = null) {
  try {
    const filter = filterStr ? (record) => {
      const [key, value] = filterStr.split("=");
      return record[key] === value;
    } : null;
    await exportData("authority_reports", outputFile, filter);
  } catch (error) {
    logger.error(`CSV export failed: ${error.message}`);
  }
}

if (require.main === module) {
  exportToCsv();
}

module.exports = { exportData, exportToCsv };