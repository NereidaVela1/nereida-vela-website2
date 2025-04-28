program
  .command("export")
  .description("Export fraud data to CSV")
  .option("-t, --type <type>", "Data type (authority_reports or fraud_events)", "authority_reports")
  .option("-o, --output <file>", "Output CSV file", "nsfr_report.csv")
  .option("-f, --filter <key=value>", "Filter data (e.g., location=North America)")
  .action(async (options) => {
    const { type, output, filter } = options;
    if (!["authority_reports", "fraud_events"].includes(type)) {
      logger.warn(`Invalid type: ${type}`);
      process.exit(1);
    }

    const filterFn = filter ? (record) => record[filter.split("=")[0]] === filter.split("=")[1] : null;
    try {
      await exportData(type, output, filterFn);
      logger.info(`Export command completed: ${output} generated!`);
    } catch (error) {
      logger.error(`Export command failed: ${error.message}`);
    } finally {
      await cleanup();
    }
  });

program
  .command("server")
  .description("Start the NSFR API server")
  .option("-p, --port <port>", "Port to run on", 3000)
  .action((options) => {
    const { port } = options;
    app.listen(port, () => logger.info(`NSFR server running on port ${port}: Ready to squash fraudsters!`));
  });

program.parse(process.argv);